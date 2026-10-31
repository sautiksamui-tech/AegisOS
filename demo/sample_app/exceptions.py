"""Sample application payment exceptions."""


class PaymentProcessingError(Exception):
    """Base exception for payment processing."""
    pass


class TransientProcessingError(PaymentProcessingError):
    """Simulated transient database/gateway error subject to fault injection."""
    pass


class PaymentValidationError(PaymentProcessingError):
    """Simulated business validation error used in negative control tests."""
    pass
