"""pytest configuration — suppresses benign collection warnings from imported enums/dataclasses."""
import warnings

from pytest import PytestCollectionWarning

warnings.filterwarnings("ignore", category=PytestCollectionWarning)
