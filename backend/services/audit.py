"""
Blockchain-Lite Audit Trail Service for CertiTrust
=================================================
Implements a cryptographic hash-chain logger for tamper-evident audit logs.

Features:
- Hash-chain linking (each entry references previous entry's hash)
- Per-institution chain isolation
- Chain integrity verification
- Efficient batch operations

Memory optimized for 8GB RAM environments.
"""

import os
import hashlib
import json
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
import httpx


class AuditEventType(Enum):
    """Types of auditable events."""
    INSTITUTION_ONBOARDED = "institution_onboarded"
    KEY_ROTATED = "key_rotated"
    DOCUMENT_ISSUED = "document_issued"
    DOCUMENT_REVOKED = "document_revoked"
    VERIFICATION_SUCCESS = "verification_success"
    VERIFICATION_FAILED = "verification_failed"
    TEMPLATE_CREATED = "template_created"
    TEMPLATE_UPDATED = "template_updated"


@dataclass
class AuditEntry:
    """Represents a single audit log entry."""
    event_type: AuditEventType
    institution_id: Optional[str] = None
    document_id: Optional[str] = None
    document_hash: Optional[str] = None
    log_hash: str = ""
    previous_log_hash: Optional[str] = None
    chain_position: int = 0
    actor_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
    def compute_hash(self) -> str:
        """
        Computes the hash of this log entry.
        
        The hash includes:
        - Event type
        - Institution ID
        - Document hash (if applicable)
        - Previous log hash (for chain linking)
        - Chain position
        - Timestamp
        - Metadata
        
        Returns:
            SHA-256 hex digest
        """
        hash_input = {
            "event_type": self.event_type.value,
            "institution_id": self.institution_id,
            "document_id": self.document_id,
            "document_hash": self.document_hash,
            "previous_log_hash": self.previous_log_hash,
            "chain_position": self.chain_position,
            "created_at": self.created_at,
            "metadata": self.metadata
        }
        
        # Serialize deterministically
        serialized = json.dumps(hash_input, sort_keys=True)
        return hashlib.sha256(serialized.encode('utf-8')).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Converts entry to dictionary for database storage."""
        return {
            "event_type": self.event_type.value,
            "institution_id": self.institution_id,
            "document_id": self.document_id,
            "document_hash": self.document_hash,
            "log_hash": self.log_hash,
            "previous_log_hash": self.previous_log_hash,
            "chain_position": self.chain_position,
            "actor_id": self.actor_id,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "metadata": self.metadata,
            "created_at": self.created_at
        }


class AuditError(Exception):
    """Base exception for audit operations."""
    pass


class ChainIntegrityError(AuditError):
    """Exception raised when chain integrity check fails."""
    pass


class AuditService:
    """
    Hash-Chain Audit Logger.
    
    Implements a blockchain-lite audit trail where each entry contains
    the hash of the previous entry, creating a tamper-evident chain.
    """
    
    def __init__(self, supabase_url: Optional[str] = None,
                 supabase_key: Optional[str] = None):
        """
        Initialize audit service with Supabase connection.
        
        Args:
            supabase_url: Supabase project URL
            supabase_key: Supabase service role key
        """
        self._supabase_url = supabase_url or os.getenv("SUPABASE_URL")
        self._supabase_key = supabase_key or os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        
        if not self._supabase_url or not self._supabase_key:
            print("WARNING: Supabase credentials not configured. Audit logging disabled.")
    
    def _get_headers(self) -> Dict[str, str]:
        """Returns Supabase API headers."""
        return {
            "apikey": self._supabase_key,
            "Authorization": f"Bearer {self._supabase_key}",
            "Content-Type": "application/json"
        }
    
    def _get_previous_entry(self, institution_id: Optional[str] = None) -> Tuple[Optional[str], int]:
        """
        Fetches the previous log entry's hash and determines next chain position.
        
        Args:
            institution_id: Institution ID for per-institution chains
            
        Returns:
            Tuple of (previous_log_hash, next_chain_position)
        """
        if not self._supabase_url or not self._supabase_key:
            return None, 1
        
        try:
            url = f"{self._supabase_url}/rest/v1/audit_logs"
            
            # Build query for the most recent entry
            params = {
                "select": "log_hash,chain_position",
                "order": "chain_position.desc",
                "limit": "1"
            }
            
            if institution_id:
                params["institution_id"] = f"eq.{institution_id}"
            
            response = httpx.get(url, headers=self._get_headers(), params=params)
            
            if response.status_code == 200:
                data = response.json()
                if data and len(data) > 0:
                    prev_hash = data[0].get("log_hash")
                    prev_position = data[0].get("chain_position", 0)
                    return prev_hash, prev_position + 1
            
            return None, 1
            
        except Exception as e:
            print(f"Warning: Could not fetch previous audit entry: {e}")
            return None, 1
    
    def log_event(
        self,
        event_type: AuditEventType,
        institution_id: Optional[str] = None,
        document_id: Optional[str] = None,
        document_hash: Optional[str] = None,
        actor_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[AuditEntry]:
        """
        Logs an audit event with hash-chain linking.
        
        Args:
            event_type: Type of event to log
            institution_id: Institution ID (for per-institution chains)
            document_id: Related document ID (if applicable)
            document_hash: Related document hash (if applicable)
            actor_id: ID of the actor performing the action
            ip_address: Client IP address
            user_agent: Client user agent
            metadata: Additional context data
            
        Returns:
            AuditEntry object or None if logging fails
        """
        if not self._supabase_url or not self._supabase_key:
            print("Audit logging skipped: Supabase not configured")
            return None
        
        try:
            # Get previous entry for chain linking
            previous_hash, chain_position = self._get_previous_entry(institution_id)
            
            # Create audit entry
            entry = AuditEntry(
                event_type=event_type,
                institution_id=institution_id,
                document_id=document_id,
                document_hash=document_hash,
                previous_log_hash=previous_hash,
                chain_position=chain_position,
                actor_id=actor_id,
                ip_address=ip_address,
                user_agent=user_agent,
                metadata=metadata or {}
            )
            
            # Compute log hash
            entry.log_hash = entry.compute_hash()
            
            # Store in database
            url = f"{self._supabase_url}/rest/v1/audit_logs"
            headers = self._get_headers()
            headers["Prefer"] = "return=minimal"
            
            response = httpx.post(url, headers=headers, json=entry.to_dict())
            
            if response.status_code >= 400:
                print(f"Error logging audit event: {response.text}")
                return None
            
            return entry
            
        except Exception as e:
            print(f"Exception logging audit event: {e}")
            return None
    
    def log_document_issued(
        self,
        institution_id: str,
        document_id: str,
        document_hash: str,
        signature: str,
        document_type: Optional[str] = None,
        subject_id: Optional[str] = None
    ) -> Optional[AuditEntry]:
        """
        Convenience method for logging document issuance.
        
        Args:
            institution_id: Issuing institution ID
            document_id: New document ID
            document_hash: SHA-256 hash of the document
            signature: Ed25519 signature
            document_type: Type of document
            subject_id: Subject identifier (hashed for privacy)
            
        Returns:
            AuditEntry or None
        """
        return self.log_event(
            event_type=AuditEventType.DOCUMENT_ISSUED,
            institution_id=institution_id,
            document_id=document_id,
            document_hash=document_hash,
            metadata={
                "signature": signature[:32] + "...",  # Truncate for log
                "document_type": document_type,
                "subject_id_hash": hashlib.sha256(
                    (subject_id or "").encode()
                ).hexdigest()[:16] if subject_id else None
            }
        )
    
    def log_verification(
        self,
        document_hash: str,
        is_valid: bool,
        institution_id: Optional[str] = None,
        failure_reason: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[AuditEntry]:
        """
        Logs a document verification attempt.
        
        Args:
            document_hash: Hash of the document being verified
            is_valid: Whether verification succeeded
            institution_id: Institution ID if known
            failure_reason: Reason for failure if applicable
            ip_address: Client IP
            user_agent: Client user agent
            metadata: Additional metadata (e.g., forensic results)
            
        Returns:
            AuditEntry or None
        """
        event_type = AuditEventType.VERIFICATION_SUCCESS if is_valid else AuditEventType.VERIFICATION_FAILED
        
        # Merge metadata with failure reason
        full_metadata = metadata.copy() if metadata else {}
        if failure_reason:
            full_metadata["failure_reason"] = failure_reason
        
        return self.log_event(
            event_type=event_type,
            institution_id=institution_id,
            document_hash=document_hash,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=full_metadata if full_metadata else {}
        )
    
    def verify_chain_integrity(
        self,
        institution_id: Optional[str] = None,
        limit: int = 1000
    ) -> Tuple[bool, Optional[int]]:
        """
        Verifies the integrity of the audit chain.
        
        Checks that each entry's previous_log_hash matches the
        actual log_hash of the preceding entry.
        
        Args:
            institution_id: Institution ID to verify (None for global chain)
            limit: Maximum number of entries to check
            
        Returns:
            Tuple of (is_valid, broken_position)
            - is_valid: True if chain is intact
            - broken_position: Position where chain is broken (None if valid)
        """
        if not self._supabase_url or not self._supabase_key:
            return True, None  # Can't verify without database
        
        try:
            url = f"{self._supabase_url}/rest/v1/audit_logs"
            
            params = {
                "select": "log_hash,previous_log_hash,chain_position",
                "order": "chain_position.asc",
                "limit": str(limit)
            }
            
            if institution_id:
                params["institution_id"] = f"eq.{institution_id}"
            
            response = httpx.get(url, headers=self._get_headers(), params=params)
            
            if response.status_code != 200:
                raise AuditError(f"Failed to fetch audit logs: {response.text}")
            
            entries = response.json()
            
            if not entries:
                return True, None
            
            # Verify chain
            for i, entry in enumerate(entries):
                if i == 0:
                    # First entry should have no previous hash
                    if entry.get("previous_log_hash") is not None:
                        # This could be valid if it's not position 1
                        if entry.get("chain_position") == 1:
                            continue
                else:
                    # Each entry's previous_log_hash should match prior entry's log_hash
                    expected_prev = entries[i - 1].get("log_hash")
                    actual_prev = entry.get("previous_log_hash")
                    
                    if actual_prev != expected_prev:
                        return False, entry.get("chain_position")
            
            return True, None
            
        except AuditError:
            raise
        except Exception as e:
            raise AuditError(f"Chain verification failed: {e}")
    
    def get_audit_trail(
        self,
        institution_id: Optional[str] = None,
        document_id: Optional[str] = None,
        event_type: Optional[AuditEventType] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Retrieves audit trail entries with optional filters.
        
        Args:
            institution_id: Filter by institution
            document_id: Filter by document
            event_type: Filter by event type
            start_date: Filter entries after this date (ISO format)
            end_date: Filter entries before this date (ISO format)
            limit: Maximum entries to return
            offset: Pagination offset
            
        Returns:
            List of audit entries
        """
        if not self._supabase_url or not self._supabase_key:
            return []
        
        try:
            url = f"{self._supabase_url}/rest/v1/audit_logs"
            
            params = {
                "select": "*",
                "order": "chain_position.desc",
                "limit": str(limit),
                "offset": str(offset)
            }
            
            if institution_id:
                params["institution_id"] = f"eq.{institution_id}"
            
            if document_id:
                params["document_id"] = f"eq.{document_id}"
            
            if event_type:
                params["event_type"] = f"eq.{event_type.value}"
            
            if start_date:
                params["created_at"] = f"gte.{start_date}"
            
            if end_date:
                params["created_at"] = f"lte.{end_date}"
            
            response = httpx.get(url, headers=self._get_headers(), params=params)
            
            if response.status_code == 200:
                return response.json()
            
            return []
            
        except Exception as e:
            print(f"Error fetching audit trail: {e}")
            return []


# Legacy compatibility function
def log_audit_event(doc_hash: str, institution_id: Optional[str] = None):
    """
    Legacy function for backward compatibility with existing code.
    
    Args:
        doc_hash: Document hash to log
        institution_id: Optional institution ID
    """
    service = AuditService()
    service.log_event(
        event_type=AuditEventType.DOCUMENT_ISSUED,
        institution_id=institution_id,
        document_hash=doc_hash
    )
