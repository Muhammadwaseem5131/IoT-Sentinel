import abc


class ReportProvider(abc.ABC):
    """Interface all AI report providers implement. One class per backend."""

    name = "base"

    def __init__(self, api_key: str = "", **kwargs):
        self.api_key = api_key

    @abc.abstractmethod
    def generate_report(self, findings_payload: dict, prompt: str) -> str:
        """Return a plain-language risk report string for the given findings."""
        raise NotImplementedError
