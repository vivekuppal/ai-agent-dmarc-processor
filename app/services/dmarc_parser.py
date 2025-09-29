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


logger = logging.getLogger(__name__)


class DMARCParser:
    """Parse DMARC XML reports and store data in database"""

    def __init__(self, db: AsyncSession):
        self.db = db

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
                            ))

                        # Store ALL DKIM results
                        for dkim_auth in record_data.get("dkim_auth_results", []):
                            s.add(DmarcReportAuthDetail(
                                dmarc_report_id=dmarc_report.id,
                                type=AuthType.DKIM,
                                domain=dkim_auth.get("domain"),
                                selector=dkim_auth.get("selector"),
                                result=AuthResult.PASS if (dkim_auth.get("result") or "").lower() == "pass" else AuthResult.FAIL,
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
        """
        1. Extract report metadata
        2. Extract policy published
        3. Extract records with authentication results
        4. Handle different XML schema versions
        """
        try:
            root = ET.fromstring(xml_content)

            # Extract report metadata
            report_metadata = root.find('report_metadata')
            org_name = report_metadata.find('org_name').text if report_metadata.find('org_name') is not None else None
            report_id = report_metadata.find('report_id').text if report_metadata.find('report_id') is not None else None

            # Extract date range
            date_range = report_metadata.find('date_range')
            date_start = datetime.utcfromtimestamp(int(date_range.find('begin').text))
            date_end = datetime.utcfromtimestamp(int(date_range.find('end').text))

            # Extract policy published
            policy_published = root.find('policy_published')
            policy_domain = policy_published.find('domain').text if policy_published.find('domain') is not None else None

            # Optional policy fields
            adkim = policy_published.find('adkim')
            aspf = policy_published.find('aspf')
            p = policy_published.find('p')
            sp = policy_published.find('sp')
            pct = policy_published.find('pct')
            np = policy_published.find('np')

            policy_data = {
                'domain': policy_domain,
                'adkim': adkim.text if adkim is not None else None,
                'aspf': aspf.text if aspf is not None else None,
                'p': p.text if p is not None else None,
                'sp': sp.text if sp is not None else None,
                'pct': int(pct.text) if pct is not None and pct.text else None,
                'np': np.text if np is not None else None
            }

            records = []
            for record in root.findall('.//record'):
                row = record.find('row')
                identifiers = record.find('identifiers')
                auth_results = record.find('auth_results')

                # Extract basic record data
                count = int(row.find('count').text)
                source_ip = row.find('source_ip').text if row.find('source_ip') is not None else None
                header_from = identifiers.find('header_from').text if identifiers.find('header_from') is not None else None
                envelope_to = identifiers.find('envelope_to').text if identifiers.find('envelope_to') is not None else None

                # Extract policy evaluation
                policy_eval = row.find('policy_evaluated')
                disposition = policy_eval.find('disposition').text if policy_eval.find('disposition') is not None else None
                dkim_result = policy_eval.find('dkim').text if policy_eval.find('dkim') is not None else None
                spf_result = policy_eval.find('spf').text if policy_eval.find('spf') is not None else None

                # Collect ALL SPF auth results
                spf_auth_results = []
                for spf_auth in auth_results.findall('spf'):
                    spf_auth_results.append({
                        "domain": spf_auth.findtext("domain"),
                        "result": spf_auth.findtext("result") or "unknown",
                    })

                # Collect ALL DKIM auth results
                dkim_auth_results = []
                for dkim_auth in auth_results.findall('dkim'):
                    dkim_auth_results.append({
                        "domain": dkim_auth.findtext("domain"),
                        "selector": dkim_auth.findtext("selector"),
                        "result": dkim_auth.findtext("result") or "unknown",
                    })

                record_data = {
                    'count': count,
                    'source_ip': source_ip,
                    'header_from': header_from,
                    'envelope_to': envelope_to,
                    'disposition': disposition,
                    'dkim_result': dkim_result,
                    'spf_result': spf_result,
                    'spf_auth_results': spf_auth_results,
                    'dkim_auth_results': dkim_auth_results,
                }

                records.append(record_data)

            parsed_data = {
                'report_metadata': {
                    'org_name': org_name,
                    'report_id': report_id,
                    'date_start': date_start,
                    'date_end': date_end
                },
                'policy_published': policy_data,
                'records': records
            }

            logger.info(f"Successfully parsed XML with {len(records)} records")
            return parsed_data

        except ET.ParseError as e:
            logger.error(f"XML parsing error: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error parsing XML: {str(e)}")
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
