import logging
from datetime import datetime
import socket
from typing import Optional
from sqlalchemy import select
import xml.etree.ElementTree as ET
from sqlalchemy.ext.asyncio import AsyncSession
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
            # End the implicit read-only transaction started by the SELECT
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
                return 0  # ensure int return

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

                        # SPF auth
                        spf_result = (record_data.get('spf_auth_result') or '').lower()
                        spf_domain = record_data.get('spf_auth_domain')
                        if spf_domain:
                            # print('parse_and_store - spf 1')
                            s.add(DmarcReportAuthDetail(
                                dmarc_report_id=dmarc_report.id,
                                type=AuthType.SPF,
                                domain=spf_domain,
                                result=AuthResult.PASS if spf_result == 'pass' else AuthResult.FAIL,
                            ))
                            # print('parse_and_store - spf 2')
                            await s.flush()  # populate dmarc_report.id
                            # print('parse_and_store - spf 3')

                        # DKIM auth
                        dkim_result = (record_data.get('dkim_auth_result') or '').lower()
                        dkim_domain = record_data.get('dkim_auth_domain')
                        dkim_selector = record_data.get('dkim_auth_selector')
                        if dkim_domain:
                            s.add(DmarcReportAuthDetail(
                                dmarc_report_id=dmarc_report.id,
                                type=AuthType.DKIM,
                                domain=dkim_domain,
                                selector=dkim_selector,
                                result=AuthResult.PASS if spf_result == 'pass' else AuthResult.FAIL,
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
            # If we’re in a tx we own, maybe_transaction will roll back automatically.
            # If we’re inside a caller tx, you can optionally roll back here:
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
        Parse XML structure - placeholder for future implementation

        This method will be expanded to:
        1. Parse XML using lxml or xml.etree.ElementTree
        2. Extract report metadata
        3. Extract policy published
        4. Extract records with authentication results
        5. Handle different XML schema versions
        """
        try:
            root = ET.fromstring(xml_content)
            # logger.info('_parse_xml_structure')
            # Extract report metadata
            report_metadata = root.find('report_metadata')
            org_name = report_metadata.find('org_name').text if report_metadata.find('org_name') is not None else None
            report_id = report_metadata.find('report_id').text if report_metadata.find('report_id') is not None else None
            # logger.info('_parse_xml_structure 1')

            # Extract date range
            date_range = report_metadata.find('date_range')
            date_start = datetime.utcfromtimestamp(
                int(date_range.find('begin').text))
            date_end = datetime.utcfromtimestamp(
                int(date_range.find('end').text))
            # logger.info('_parse_xml_structure 2')

            # Extract policy published
            policy_published = root.find('policy_published')
            policy_domain = policy_published.find('domain').text if policy_published.find('domain') is not None else None
            # logger.info('_parse_xml_structure 3')

            # Optional policy fields
            adkim = policy_published.find('adkim')
            aspf = policy_published.find('aspf')
            p = policy_published.find('p')
            sp = policy_published.find('sp')
            pct = policy_published.find('pct')
            np = policy_published.find('np')
            # logger.info('_parse_xml_structure 4')

            policy_data = {
                'domain': policy_domain,
                'adkim': adkim.text if adkim is not None else None,
                'aspf': aspf.text if aspf is not None else None,
                'p': p.text if p is not None else None,
                'sp': sp.text if sp is not None else None,
                'pct': int(pct.text) if pct is not None and pct.text else None,
                'np': np.text if np is not None else None
            }

            # Extract all records
            records = []
            for record in root.findall('.//record'):
                row = record.find('row')
                identifiers = record.find('identifiers')
                auth_results = record.find('auth_results')
                # logger.info('_parse_xml_structure 5')

                # Extract basic record data
                count = int(row.find('count').text)
                source_ip = row.find('source_ip').text if row.find('source_ip') is not None else None
                header_from = identifiers.find('header_from').text if identifiers.find('header_from') is not None else None
                envelope_to = identifiers.find('envelope_to').text if identifiers.find('envelope_to') is not None else None
                # logger.info('_parse_xml_structure 6')

                # Extract policy evaluation
                policy_eval = row.find('policy_evaluated')
                disposition = policy_eval.find('disposition').text if policy_eval.find('disposition') is not None else None
                dkim_result = policy_eval.find('dkim').text if policy_eval.find('dkim') is not None else None
                spf_result = policy_eval.find('spf').text if policy_eval.find('spf') is not None else None
                # logger.info('_parse_xml_structure 7')

                # Extract authentication results details
                spf_auth = auth_results.find('spf')
                dkim_auth = auth_results.find('dkim')
                # logger.info('_parse_xml_structure 8')

                spf_auth_result = None
                spf_auth_domain = None

                if spf_auth:
                    spf_auth_result = spf_auth.find('result').text if spf_auth.find('result') is not None else 'unknown'
                    spf_auth_domain = spf_auth.find('domain').text if spf_auth.find('domain') is not None else None
                # logger.info('_parse_xml_structure 9')

                dkim_auth_result = None
                dkim_auth_domain = None
                dkim_auth_selector = None

                if dkim_auth:
                    dkim_auth_result = dkim_auth.find('result').text if dkim_auth.find('result') is not None else 'unknown'
                    dkim_auth_domain = dkim_auth.find('domain').text if dkim_auth.find('domain') is not None else None
                    dkim_auth_selector = dkim_auth.find('selector').text if dkim_auth.find('selector') is not None else None
                # logger.info('_parse_xml_structure 10')

                record_data = {
                    'count': count,
                    'source_ip': source_ip,
                    'header_from': header_from,
                    'envelope_to': envelope_to,
                    'disposition': disposition,
                    'dkim_result': dkim_result,
                    'spf_result': spf_result,
                    'spf_auth_result': spf_auth_result,
                    'dkim_auth_result': dkim_auth_result,
                    'spf_auth_domain': spf_auth_domain,
                    'dkim_auth_domain': dkim_auth_domain,
                    'dkim_auth_selector': dkim_auth_selector
                }

                records.append(record_data)
                # logger.info('_parse_xml_structure 11')

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

        # For subdomains like mail.example.com, extract example.com as main domain
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
            # dkim_auth_result = record_data.get('dkim_auth_result', '').lower()
            # spf_auth_result = record_data.get('spf_auth_result', '').lower()

            # logger.info(f"disposition: {disposition}")
            # logger.info(f"dkim_result: {dkim_result}")
            # logger.info(f"spf_result: {spf_result}")
            # logger.info(f"dkim_auth_result: {dkim_auth_result}")
            # logger.info(f"spf_auth_result: {spf_auth_result}")

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

            # # Rule 1: Full Success - disposition=none, all policy and auth results pass
            # if (disposition == "none" and
            #     dkim_result == "pass" and
            #     spf_result == "pass" and
            #     dkim_auth_result == "pass" and
            #     spf_auth_result == "pass"):
            #     return EmailStatus.SUCCESS, EmailStatusReason.SUCCESS

            # # Rule 2: Quarantine - disposition=quarantine
            # if disposition == "quarantine":
            #     return EmailStatus.FAILURE, EmailStatusReason.SPAM

            # # Rule 3: Reject - disposition=reject
            # if disposition == "reject":
            #     return EmailStatus.FAILURE, EmailStatusReason.NOT_DELIVERED

            # # Rule 4: disposition=none, DKIM fail, SPF pass
            # if (disposition == "none" and
            #     dkim_result == "fail" and
            #     spf_result == "pass"):
            #     return EmailStatus.FAILURE, EmailStatusReason.DKIM_FAILED

            # # Rule 5: disposition=none, DKIM pass, SPF fail
            # if (disposition == "none" and
            #     dkim_result == "pass" and
            #     spf_result == "fail"):
            #     return EmailStatus.FAILURE, EmailStatusReason.SPF_FAILED

            # # Rule 6: disposition=none, both DKIM and SPF fail
            # if (disposition == "none" and
            #     dkim_result == "fail" and
            #     spf_result == "fail"):
            #     return EmailStatus.FAILURE, EmailStatusReason.SPF_AND_DKIM_FAILED

            return email_status, email_status_reason

        except Exception as e:
            logger.error(f"Error determining email status: {str(e)}")
            return EmailStatus.FAILURE, EmailStatusReason.MIXED
