"""Shared test fixtures."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from prompt_guard.model import PromptGuardModel
from prompt_guard.service import PromptGuardServicer


@pytest.fixture()
def mock_model() -> MagicMock:
    """A mock PromptGuardModel that returns configurable results."""
    model = MagicMock(spec=PromptGuardModel)
    model.model_name = "test-model"
    model.device = "cpu"
    model.ready = True
    model.classify.return_value = ("INJECTION", 0.95)
    return model


@pytest.fixture()
def servicer(mock_model: MagicMock) -> PromptGuardServicer:
    """A PromptGuardServicer backed by a mock model."""
    return PromptGuardServicer(mock_model)
