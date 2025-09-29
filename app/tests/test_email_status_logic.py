"""
Test cases for email status evaluation business logic.

This module tests the 7 business rules for determining email delivery status
based on DMARC XML record data.
"""

import pytest
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.dmarc_parser import DMARCParser
from app.models import EmailStatus, EmailStatusReason


class TestEmailStatusEvaluation:
    """Test class for email status evaluation business logic."""

    @pytest.fixture
    def parser(self):
        """Create DMARCParser instance for testing."""
        return DMARCParser(db=None)  # No database needed for logic testing

    def test_rule_1_full_success(self, parser):
        """
        Test Rule 1: Full Success
        When disposition=none AND all DKIM/SPF policy and auth results pass
        Then email_status=Success AND email_status_reason=Success
        """
        record_data = {
            'disposition': 'none',
            'policy_dkim': 'pass',
            'policy_spf': 'pass',
            'dkim_auth_result': 'pass',
            'spf_auth_result': 'pass',
            'count': 10
        }
        
        status, reason = parser._determine_email_status(record_data)
        
        assert status == EmailStatus.SUCCESS
        assert reason == EmailStatusReason.SUCCESS

    def test_rule_1_case_insensitive(self, parser):
        """Test that Rule 1 works with different case variations."""
        record_data = {
            'disposition': 'NONE',
            'policy_dkim': 'PASS',
            'policy_spf': 'Pass',
            'dkim_auth_result': 'pass',
            'spf_auth_result': 'PASS',
            'count': 5
        }
        
        status, reason = parser._determine_email_status(record_data)
        
        assert status == EmailStatus.SUCCESS
        assert reason == EmailStatusReason.SUCCESS

    def test_rule_2_quarantine_spam(self, parser):
        """
        Test Rule 2: Quarantine (Spam)
        When disposition=quarantine
        Then email_status=Failure AND email_status_reason=Spam
        """
        record_data = {
            'disposition': 'quarantine',
            'policy_dkim': 'pass',  # Other values don't matter
            'policy_spf': 'fail',   # for quarantine rule
            'dkim_auth_result': 'pass',
            'spf_auth_result': 'fail',
            'count': 3
        }
        
        status, reason = parser._determine_email_status(record_data)
        
        assert status == EmailStatus.FAILURE
        assert reason == EmailStatusReason.SPAM

    def test_rule_3_reject_not_delivered(self, parser):
        """
        Test Rule 3: Reject (Not Delivered)
        When disposition=reject
        Then email_status=Failure AND email_status_reason=Not Delivered
        """
        record_data = {
            'disposition': 'reject',
            'policy_dkim': 'fail',  # Other values don't matter
            'policy_spf': 'fail',   # for reject rule
            'dkim_auth_result': 'fail',
            'spf_auth_result': 'fail',
            'count': 1
        }
        
        status, reason = parser._determine_email_status(record_data)
        
        assert status == EmailStatus.FAILURE
        assert reason == EmailStatusReason.NOT_DELIVERED

    def test_rule_4_dkim_failed(self, parser):
        """
        Test Rule 4: DKIM Failed
        When disposition=none AND policy_dkim=fail AND policy_spf=pass
        Then email_status=Failure AND email_status_reason=DKIM_FAILED
        """
        record_data = {
            'disposition': 'none',
            'policy_dkim': 'fail',
            'policy_spf': 'pass',
            'dkim_auth_result': 'fail',
            'spf_auth_result': 'pass',
            'count': 7
        }
        
        status, reason = parser._determine_email_status(record_data)
        
        assert status == EmailStatus.FAILURE
        assert reason == EmailStatusReason.DKIM_FAILED

    def test_rule_5_spf_failed(self, parser):
        """
        Test Rule 5: SPF Failed
        When disposition=none AND policy_dkim=pass AND policy_spf=fail
        Then email_status=Failure AND email_status_reason=SPF_FAILED
        """
        record_data = {
            'disposition': 'none',
            'policy_dkim': 'pass',
            'policy_spf': 'fail',
            'dkim_auth_result': 'pass',
            'spf_auth_result': 'fail',
            'count': 2
        }
        
        status, reason = parser._determine_email_status(record_data)
        
        assert status == EmailStatus.FAILURE
        assert reason == EmailStatusReason.SPF_FAILED

    def test_rule_6_both_spf_and_dkim_failed(self, parser):
        """
        Test Rule 6: Both SPF and DKIM Failed
        When disposition=none AND policy_dkim=fail AND policy_spf=fail
        Then email_status=Failure AND email_status_reason=SPF_AND_DKIM_FAILED
        """
        record_data = {
            'disposition': 'none',
            'policy_dkim': 'fail',
            'policy_spf': 'fail',
            'dkim_auth_result': 'fail',
            'spf_auth_result': 'fail',
            'count': 15
        }
        
        status, reason = parser._determine_email_status(record_data)
        
        assert status == EmailStatus.FAILURE
        assert reason == EmailStatusReason.SPF_AND_DKIM_FAILED

    def test_rule_7_mixed_case_1(self, parser):
        """
        Test Rule 7: Mixed Case 1
        When disposition=none but policy and auth results don't align for success
        Then email_status=Failure AND email_status_reason=Mixed
        """
        record_data = {
            'disposition': 'none',
            'policy_dkim': 'pass',
            'policy_spf': 'pass',
            'dkim_auth_result': 'fail',  # This breaks the success rule
            'spf_auth_result': 'pass',
            'count': 4
        }
        
        status, reason = parser._determine_email_status(record_data)
        
        assert status == EmailStatus.FAILURE
        assert reason == EmailStatusReason.MIXED

    def test_rule_7_mixed_case_2(self, parser):
        """
        Test Rule 7: Mixed Case 2 - True Mixed Case
        When disposition=none and conditions don't match any specific rule
        Then email_status=Failure AND email_status_reason=Mixed
        """
        record_data = {
            'disposition': 'none',
            'policy_dkim': 'unknown',  # Invalid policy value
            'policy_spf': 'pass',
            'dkim_auth_result': 'pass',
            'spf_auth_result': 'pass',
            'count': 6
        }
        
        status, reason = parser._determine_email_status(record_data)
        
        assert status == EmailStatus.FAILURE
        assert reason == EmailStatusReason.MIXED

    def test_missing_values_default_to_mixed(self, parser):
        """
        Test that missing or empty values default to Mixed status.
        """
        record_data = {
            'disposition': '',
            'policy_dkim': '',
            'policy_spf': '',
            'dkim_auth_result': '',
            'spf_auth_result': '',
            'count': 1
        }
        
        status, reason = parser._determine_email_status(record_data)
        
        assert status == EmailStatus.FAILURE
        assert reason == EmailStatusReason.MIXED

    def test_unknown_disposition_mixed(self, parser):
        """
        Test that unknown disposition values result in Mixed status.
        """
        record_data = {
            'disposition': 'unknown',
            'policy_dkim': 'pass',
            'policy_spf': 'pass',
            'dkim_auth_result': 'pass',
            'spf_auth_result': 'pass',
            'count': 1
        }
        
        status, reason = parser._determine_email_status(record_data)
        
        assert status == EmailStatus.FAILURE
        assert reason == EmailStatusReason.MIXED

    @pytest.mark.parametrize("disposition,expected_status,expected_reason", [
        ("quarantine", EmailStatus.FAILURE, EmailStatusReason.SPAM),
        ("reject", EmailStatus.FAILURE, EmailStatusReason.NOT_DELIVERED),
        ("QUARANTINE", EmailStatus.FAILURE, EmailStatusReason.SPAM),
        ("REJECT", EmailStatus.FAILURE, EmailStatusReason.NOT_DELIVERED),
    ])
    def test_disposition_priority_rules(self, parser, disposition, expected_status, expected_reason):
        """
        Test that disposition=quarantine and disposition=reject take priority
        regardless of other field values.
        """
        record_data = {
            'disposition': disposition,
            'policy_dkim': 'pass',
            'policy_spf': 'pass',
            'dkim_auth_result': 'pass',
            'spf_auth_result': 'pass',
            'count': 1
        }
        
        status, reason = parser._determine_email_status(record_data)
        
        assert status == expected_status
        assert reason == expected_reason

    def test_exception_handling(self, parser):
        """
        Test that exceptions in status determination default to Mixed.
        """
        # Pass None to trigger exception
        status, reason = parser._determine_email_status(None)
        
        assert status == EmailStatus.FAILURE
        assert reason == EmailStatusReason.MIXED

    def test_email_count_extraction(self, parser):
        """
        Test that email count values are correctly preserved
        (though not used in status logic, they should be available).
        """
        test_counts = [1, 5, 10, 100, 1000]
        
        for count in test_counts:
            record_data = {
                'disposition': 'none',
                'policy_dkim': 'pass',
                'policy_spf': 'pass',
                'dkim_auth_result': 'pass',
                'spf_auth_result': 'pass',
                'count': count
            }
            
            # Status logic doesn't use count, but it should be preserved
            status, reason = parser._determine_email_status(record_data)
            assert status == EmailStatus.SUCCESS
            assert reason == EmailStatusReason.SUCCESS
            assert record_data['count'] == count


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.fixture
    def parser(self):
        """Create DMARCParser instance for testing."""
        return DMARCParser(db=None)

    def test_none_values(self, parser):
        """Test handling of None values in record data."""
        record_data = {
            'disposition': None,
            'policy_dkim': None,
            'policy_spf': None,
            'dkim_auth_result': None,
            'spf_auth_result': None,
            'count': 1
        }
        
        status, reason = parser._determine_email_status(record_data)
        
        assert status == EmailStatus.FAILURE
        assert reason == EmailStatusReason.MIXED

    def test_empty_dict(self, parser):
        """Test handling of empty record data."""
        record_data = {}
        
        status, reason = parser._determine_email_status(record_data)
        
        assert status == EmailStatus.FAILURE
        assert reason == EmailStatusReason.MIXED

    def test_partial_data(self, parser):
        """Test handling of incomplete record data."""
        record_data = {
            'disposition': 'none',
            'policy_dkim': 'pass',
            # Missing other required fields
        }
        
        status, reason = parser._determine_email_status(record_data)
        
        assert status == EmailStatus.FAILURE
        assert reason == EmailStatusReason.MIXED


class TestBusinessRuleOrder:
    """Test that business rules are applied in the correct priority order."""

    @pytest.fixture
    def parser(self):
        """Create DMARCParser instance for testing."""
        return DMARCParser(db=None)

    def test_quarantine_overrides_success_conditions(self, parser):
        """
        Test that quarantine disposition overrides what would otherwise be success.
        """
        record_data = {
            'disposition': 'quarantine',  # This should override everything else
            'policy_dkim': 'pass',
            'policy_spf': 'pass',
            'dkim_auth_result': 'pass',
            'spf_auth_result': 'pass',
            'count': 5
        }
        
        status, reason = parser._determine_email_status(record_data)
        
        # Should be SPAM, not SUCCESS, because quarantine takes priority
        assert status == EmailStatus.FAILURE
        assert reason == EmailStatusReason.SPAM

    def test_reject_overrides_spf_dkim_rules(self, parser):
        """
        Test that reject disposition overrides SPF/DKIM specific failure rules.
        """
        record_data = {
            'disposition': 'reject',  # This should override SPF/DKIM logic
            'policy_dkim': 'fail',
            'policy_spf': 'pass',  # Would normally be DKIM_FAILED
            'dkim_auth_result': 'fail',
            'spf_auth_result': 'pass',
            'count': 3
        }
        
        status, reason = parser._determine_email_status(record_data)
        
        # Should be NOT_DELIVERED, not DKIM_FAILED, because reject takes priority
        assert status == EmailStatus.FAILURE
        assert reason == EmailStatusReason.NOT_DELIVERED


if __name__ == "__main__":
    # Allow running tests directly with python
    pytest.main([__file__, "-v"])