import logging
import socket
from typing import Optional
import xml.etree.ElementTree as ET
from models import (
    DMARCReport,
    EmailStatus,
    EmailStatusReason,
    Domain,
    DmarcReportAuthDetail,
)


logger = logging.getLogger(__name__)


class DMARCParser:
    """Parse DMARC XML reports and store data in database"""

    def __init__(self, db):
        self.db = db

    def lookup_customer_id(self, policy_domain: str) -> Optional[int]:
        """
        Lookup customer_id for a given policy domain

        Args:
            policy_domain: The domain from the DMARC policy

        Returns:
            Optional[int]: customer_id if found, None otherwise
        """
        try:
            domain_record = self.db.session.query(Domain).filter(
                Domain.domain == policy_domain
            ).first()

            if domain_record:
                logger.info(f"Found customer_id {domain_record.customer_id} for domain {policy_domain}")
                return domain_record.customer_id
            else:
                logger.info(f"No customer mapping found for domain {policy_domain}")
                return None

        except Exception as e:
            logger.error(f"Error looking up customer for domain {policy_domain}: {str(e)}")
            return None

    def parse_and_store(self, xml_content: bytes, file_path: str, report_source: str) -> int:
        """
        Parse DMARC XML content and store in database

        Returns:
            int: dmarc_report_id if successful, 0 if failed
        """
        try:
            logger.info(f"Parsing DMARC report from {report_source}: {file_path}")

            # Parse XML structure
            parsed_data = self._parse_xml_structure(xml_content)
            if not parsed_data:
                logger.error(f"Failed to parse XML structure from {file_path}")
                return False

            # Lookup customer_id for the policy domain
            policy_domain = parsed_data['policy_published']['domain']
            customer_id = self.lookup_customer_id(policy_domain)

            # Create the main DMARC report record
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
                report_file=file_path
            )

            self.db.session.add(dmarc_report)
            self.db.session.flush()  # Get the ID for the foreign key

            # Create detail records for each email record in the report
            details_stored = 0
            for record_data in parsed_data.get('records', []):
                try:
                    # Determine email status using the new logic
                    email_status, email_status_reason = self._determine_email_status(record_data)
                    hostname = self.get_hostname(record_data.get('source_ip', ''))

                    # Create DMARC report detail record
                    from models import DMARCReportDetail
                    detail_record = DMARCReportDetail(
                        dmarc_report_id=dmarc_report.id,
                        email_status=email_status,
                        email_status_reason=email_status_reason,
                        email_count=record_data.get('count', 1),
                        source_ip=record_data.get('source_ip'),
                        # Will be populated later with reverse DNS lookup
                        hostname=hostname,
                        from_domain=record_data.get('header_from'),
                        to_domain=record_data.get('envelope_to')
                    )

                    self.db.session.add(detail_record)
                    details_stored += 1

                    # Add SPF record to DmarcReportAuthDetail
                    spf_result = (record_data.get('spf_auth_result') or '').lower()
                    spf_domain = record_data.get('spf_auth_domain')

                    if spf_domain:
                        spf_auth = DmarcReportAuthDetail(
                            dmarc_report_id=dmarc_report.id,
                            type='spf',
                            domain=spf_domain,
                            result='pass' if spf_result == 'pass' else 'fail'
                        )
                        self.db.session.add(spf_auth)

                    # Add DKIM record to DmarcReportAuthDetail
                    dkim_result = (record_data.get('dkim_auth_result') or '').lower()
                    dkim_domain = record_data.get('dkim_auth_domain')
                    dkim_selector = record_data.get('dkim_auth_selector')

                    if dkim_domain:
                        dkim_auth = DmarcReportAuthDetail(
                            dmarc_report_id=dmarc_report.id,
                            type='dkim',
                            domain=dkim_domain,
                            selector=dkim_selector,
                            result='pass' if dkim_result == 'pass' else 'fail'
                        )
                        self.db.session.add(dkim_auth)

                except Exception as e:
                    logger.error(f"Failed to store detail record: {str(e)}")
                    continue

            # Commit all records
            self.db.session.commit()
            logger.info(f"Successfully parsed and stored 1 report with \
                        {details_stored} detail records from {file_path}")
            return dmarc_report.id

        except Exception as e:
            logger.error(f"Error parsing DMARC report {file_path}: {str(e)}")
            self.db.session.rollback()
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
            from datetime import datetime

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
