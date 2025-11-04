# app/services/dmarc_parser.py
import logging
from datetime import datetime
import socket
from typing import Optional
import xml.etree.ElementTree as ET
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models import (
    DMARCReport,
    EmailStatus,
    EmailStatusReason,
    Domain,
    DmarcReportAuthDetail,
    DMARCReportDetail,
    AuthType,
    AuthResult
)
from app.db import maybe_transaction
from app.xml import dmarc


logger = logging.getLogger(__name__)

# These are used to help identify known forwarders
KNOWN_FORWARDER_DOMAINS = {
    # common forwarders / gateways / list hosts / relays
    "mailspamprotection.com", "mimecast.com", "proofpoint.com", "ppe-hosted.com",
    "outlook.com", "protection.outlook.com", "google.com", "sendgrid.net",
    "amazonses.com", "sparkpostmail.com", "icloud.com", "yahoo.com",
    "pphosted.com", "secureserver.net", "sendinblue.com", "mailgun.org",
}


class DMARCParser:
    """Parse DMARC XML reports and store data in database"""

    def __init__(self, db: AsyncSession):
        self.db = db

    @staticmethod
    def _relaxed_aligned(dkim_domain: Optional[str], header_from: Optional[str]) -> bool:
        """
        Approximate DMARC 'relaxed' alignment for DKIM:
        passing if DKIM d= is the same as or a parent of header_from.
        (No PSL here; use a simple suffix test as a heuristic.)
        """
        if not dkim_domain or not header_from:
            return False
        d = dkim_domain.lower().strip()
        h = header_from.lower().strip()
        return h == d or h.endswith("." + d) or d.endswith("." + h)

    @staticmethod
    def _contains_known_forwarder(dkim_auth_results: list) -> bool:
        for item in dkim_auth_results or []:
            dom = (item.get("domain") or "").lower()
            if any(dom.endswith(k) for k in KNOWN_FORWARDER_DOMAINS):
                if (item.get("result") or "").lower() == "pass":
                    return True
        return False

    def _classify_record(self, record_data: dict) -> Optional[str]:
        """
        Return a short classification string (e.g., 'forwarded') or None.

        Heuristic for forwarding/relaying:
          - policy SPF = fail
          - policy DKIM = pass
          - AND (a DKIM signature looks aligned with header_from  OR a known forwarder signed it)
        """
        try:
            spf_policy = (record_data.get("spf_result") or "").lower()
            dkim_policy = (record_data.get("dkim_result") or "").lower()
            header_from = (record_data.get("header_from") or "").lower()
            dkim_auth = record_data.get("dkim_auth_results") or []

            if spf_policy == "fail" and dkim_policy == "pass":
                # (A) aligned DKIM d= with header_from?
                aligned_pass = any(
                    self._relaxed_aligned((item.get("domain") or ""), header_from) and
                    (item.get("result") or "").lower() == "pass"
                    for item in dkim_auth
                )

                # (B) or signed by a known forwarder/gateway?
                known_forwarder = self._contains_known_forwarder(dkim_auth)

                if aligned_pass or known_forwarder:
                    return "forwarded"

            return None
        except Exception as e:
            logger.warning(f"Classification failed for record: {e}")
            return None

    async def lookup_customer_id(self, policy_domain: str) -> Optional[int]:
        """
        Lookup customer_id for a given policy domain using AsyncSession.
        """
        try:
            # Efficient: select only the needed column
            result = await self.db.execute(
                select(Domain.customer_id).where(Domain.domain == policy_domain)
            )
            customer_id = result.scalar_one_or_none()

            if customer_id is not None:
                logger.info(f"Found customer_id {customer_id} for domain {policy_domain}")
                return customer_id
            else:
                logger.info(f"No customer mapping found for domain {policy_domain}")
                return None

        except Exception as e:
            logger.error(f"Error looking up customer for domain {policy_domain}: {str(e)}")
            return None

        finally:
            if self.db.in_transaction():
                await self.db.rollback()

    async def parse_and_store(self, xml_content: bytes, file_path: str, report_source: str) -> int:
        """
        Parse DMARC XML content and store in database.
        Returns dmarc_report_id if successful, 0 if failed.
        """
        try:
            logger.info(f"Parsing DMARC report from {report_source}: {file_path}")

            # 1) Parse XML
            parsed_data = self._parse_xml_structure(xml_content)
            if not parsed_data:
                logger.error(f"Failed to parse XML structure from {file_path}")
                return 0

            # 2) Lookup customer for policy domain
            policy_domain = parsed_data['policy_published']['domain']
            customer_id: Optional[int] = await self.lookup_customer_id(policy_domain)

            # 3) Build main report row
            dmarc_report = DMARCReport(
                report_source=parsed_data['report_metadata']['org_name'],
                report_start_date=parsed_data['report_metadata']['date_start'],
                report_end_date=parsed_data['report_metadata']['date_end'],
                report_id=parsed_data['report_metadata']['report_id'],
                policy_domain=policy_domain,
                customer_id=customer_id,
                adkim=parsed_data['policy_published'].get('adkim'),
                aspf=parsed_data['policy_published'].get('aspf'),
                p=parsed_data['policy_published'].get('p'),
                sp=parsed_data['policy_published'].get('sp'),
                pct=parsed_data['policy_published'].get('pct'),
                np=parsed_data['policy_published'].get('np'),
                report_file=file_path,
            )

            details_stored = 0

            # 4) Transaction: insert main report + details + auth rows atomically
            async with maybe_transaction(self.db) as s:
                s.add(dmarc_report)
                await s.flush()  # populate dmarc_report.id

                # Details & auth
                for record_data in parsed_data.get('records', []):
                    try:
                        email_status, email_status_reason = self._determine_email_status(record_data)
                        hostname = self.get_hostname(record_data.get('source_ip', ''))

                        detail = DMARCReportDetail(
                            dmarc_report_id=dmarc_report.id,
                            email_status=email_status,
                            email_status_reason=email_status_reason,
                            email_count=record_data.get('count', 1),
                            source_ip=record_data.get('source_ip'),
                            hostname=hostname,  # may be refined via rDNS later
                            from_domain=record_data.get('header_from'),
                            to_domain=record_data.get('envelope_to'),
                            classification=self._classify_record(record_data),
                        )
                        s.add(detail)
                        details_stored += 1

                        # Store ALL SPF results
                        for spf_auth in record_data.get("spf_auth_results", []):
                            s.add(DmarcReportAuthDetail(
                                dmarc_report_id=dmarc_report.id,
                                type=AuthType.SPF,
                                domain=spf_auth.get("domain"),
                                result=AuthResult.PASS if (spf_auth.get("result") or "").lower() == "pass" else AuthResult.FAIL,
                                count=record_data.get('count', 1),
                            ))

                        # Store ALL DKIM results
                        for dkim_auth in record_data.get("dkim_auth_results", []):
                            s.add(DmarcReportAuthDetail(
                                dmarc_report_id=dmarc_report.id,
                                type=AuthType.DKIM,
                                domain=dkim_auth.get("domain"),
                                selector=dkim_auth.get("selector"),
                                result=AuthResult.PASS if (dkim_auth.get("result") or "").lower() == "pass" else AuthResult.FAIL,
                                count=record_data.get('count', 1),
                            ))

                    except Exception as e:
                        logger.error(f"Failed to store detail record: {str(e)}")
                        continue

            logger.info(
                f"Successfully parsed and stored 1 report (id={dmarc_report.id}) "
                f"with {details_stored} detail records from {file_path}"
            )
            return dmarc_report.id or 0

        except Exception as e:
            logger.error(f"Error parsing DMARC report {file_path}: {str(e)}")
            if self.db.in_transaction():
                try:
                    await self.db.rollback()
                except Exception:
                    pass
            return 0

    def get_hostname(self, ip_address: bytes) -> str:
        """Return hostname for the given ip_address"""
        try:
            if not ip_address:
                return ''
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            return hostname
        except socket.herror as e:
            logger.error(f"Unable to resolve {ip_address}: {e}")
            return ''

    def _parse_xml_structure(self, xml_content: bytes) -> Optional[dict]:
        try:
            root = dmarc.parse(xml_content)
            ns = dmarc.detect_default_ns(root)

            report_metadata = dmarc.find(root, "report_metadata", ns)
            org_name = dmarc.text(dmarc.find(report_metadata, "org_name", ns))
            report_id = dmarc.text(dmarc.find(report_metadata, "report_id", ns))

            date_range = dmarc.find(report_metadata, "date_range", ns)
            date_start = datetime.utcfromtimestamp(int(dmarc.text(dmarc.find(date_range, "begin", ns)) or "0"))
            date_end = datetime.utcfromtimestamp(int(dmarc.text(dmarc.find(date_range, "end", ns)) or "0"))

            policy_published = dmarc.find(root, "policy_published", ns)
            policy_domain = dmarc.text(dmarc.find(policy_published, "domain", ns))

            policy_data = {
                "domain": policy_domain,
                "adkim": dmarc.text(dmarc.find(policy_published, "adkim", ns)),
                "aspf":  dmarc.text(dmarc.find(policy_published, "aspf", ns)),
                "p":     dmarc.text(dmarc.find(policy_published, "p", ns)),
                "sp":    dmarc.text(dmarc.find(policy_published, "sp", ns)),
                "pct":   int(dmarc.text(dmarc.find(policy_published, "pct", ns)) or "0") or None,
                "np":    dmarc.text(dmarc.find(policy_published, "np", ns)),
            }

            records = []
            for record in dmarc.findall(root, "record", ns):
                row = dmarc.find(record, "row", ns)
                identifiers = dmarc.find(record, "identifiers", ns)
                auth_results = dmarc.find(record, "auth_results", ns)

                count = int(dmarc.text(dmarc.find(row, "count", ns)) or "0")
                source_ip = dmarc.text(dmarc.find(row, "source_ip", ns))
                header_from = dmarc.text(dmarc.find(identifiers, "header_from", ns))
                envelope_to = dmarc.text(dmarc.find(identifiers, "envelope_to", ns))

                policy_eval = dmarc.find(row, "policy_evaluated", ns)
                disposition = dmarc.text(dmarc.find(policy_eval, "disposition", ns))
                dkim_result = dmarc.text(dmarc.find(policy_eval, "dkim", ns))
                spf_result = dmarc.text(dmarc.find(policy_eval, "spf", ns))

                spf_auth_results = []
                for spf_auth in dmarc.findall(auth_results, "spf", ns):
                    spf_auth_results.append({
                        "domain": dmarc.text(dmarc.find(spf_auth, "domain", ns)),
                        "result": dmarc.text(dmarc.find(spf_auth, "result", ns)) or "unknown",
                    })

                dkim_auth_results = []
                for dkim_auth in dmarc.findall(auth_results, "dkim", ns):
                    dkim_auth_results.append({
                        "domain":   dmarc.text(dmarc.find(dkim_auth, "domain", ns)),
                        "selector": dmarc.text(dmarc.find(dkim_auth, "selector", ns)),
                        "result":   dmarc.text(dmarc.find(dkim_auth, "result", ns)) or "unknown",
                    })

                records.append({
                    "count": count,
                    "source_ip": source_ip,
                    "header_from": header_from,
                    "envelope_to": envelope_to,
                    "disposition": disposition,
                    "dkim_result": dkim_result,
                    "spf_result": spf_result,
                    "spf_auth_results": spf_auth_results,
                    "dkim_auth_results": dkim_auth_results,
                })

            return {
                "report_metadata": {
                    "org_name": org_name,
                    "report_id": report_id,
                    "date_start": date_start,
                    "date_end": date_end,
                },
                "policy_published": policy_data,
                "records": records,
            }

        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error parsing XML: {e}")
            return None

    def _extract_sender_info(self, domain: str) -> tuple:
        """
        Extract sender domain and subdomain

        Args:
            domain: Full domain name

        Returns:
            tuple: (sender_domain, sender_subdomain)
        """
        if not domain:
            return None, None

        parts = domain.split('.')
        if len(parts) <= 2:
            return domain, None

        main_domain = '.'.join(parts[-2:])
        subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else None

        return main_domain, subdomain

    def _determine_email_status(self, record_data: dict) -> tuple:
        """
        Determine email status and reason based on DMARC record data

        Args:
            record_data: Dictionary containing parsed record information

        Returns:
            tuple: (EmailStatus, EmailStatusReason)
        """
        try:
            # Extract values from record_data
            disposition = record_data.get('disposition', '').lower()
            dkim_result = record_data.get('dkim_result', '').lower()
            spf_result = record_data.get('spf_result', '').lower()

            email_status: EmailStatus = EmailStatus.FAILURE
            email_status_reason: EmailStatusReason = EmailStatusReason.MIXED

            if (disposition == "none" and
               (dkim_result == "pass" or spf_result == "pass")):
                email_status = EmailStatus.SUCCESS
            else:
                email_status = EmailStatus.FAILURE

            if (disposition == "none" and
               (dkim_result == "pass" or spf_result == "pass")):
                email_status_reason = EmailStatusReason.SUCCESS
            elif (disposition == "none" and dkim_result == "fail" and
                  spf_result == "pass"):
                email_status_reason = EmailStatusReason.DKIM_FAILED
            elif (disposition == "none" and spf_result == "fail" and
                  dkim_result == "pass"):
                email_status_reason = EmailStatusReason.SPF_FAILED
            elif (disposition == "none" and spf_result == "fail" and
                  dkim_result == "fail"):
                email_status_reason = EmailStatusReason.SPF_AND_DKIM_FAILED
            elif disposition == "quarantine":
                email_status_reason = EmailStatusReason.SPAM
            elif disposition == "reject":
                email_status_reason = EmailStatusReason.NOT_DELIVERED
            else:
                email_status_reason = EmailStatusReason.MIXED

            return email_status, email_status_reason

        except Exception as e:
            logger.error(f"Error determining email status: {str(e)}")
            return EmailStatus.FAILURE, EmailStatusReason.MIXED
