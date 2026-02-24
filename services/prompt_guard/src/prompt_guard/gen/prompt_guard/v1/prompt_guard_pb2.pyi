from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ClassifyRequest(_message.Message):
    __slots__ = ("text",)
    TEXT_FIELD_NUMBER: _ClassVar[int]
    text: str
    def __init__(self, text: _Optional[str] = ...) -> None: ...

class ClassifyResponse(_message.Message):
    __slots__ = ("label", "confidence", "latency_ms", "model_name")
    LABEL_FIELD_NUMBER: _ClassVar[int]
    CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    LATENCY_MS_FIELD_NUMBER: _ClassVar[int]
    MODEL_NAME_FIELD_NUMBER: _ClassVar[int]
    label: str
    confidence: float
    latency_ms: float
    model_name: str
    def __init__(self, label: _Optional[str] = ..., confidence: _Optional[float] = ..., latency_ms: _Optional[float] = ..., model_name: _Optional[str] = ...) -> None: ...

class ClassifyBatchRequest(_message.Message):
    __slots__ = ("texts",)
    TEXTS_FIELD_NUMBER: _ClassVar[int]
    texts: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, texts: _Optional[_Iterable[str]] = ...) -> None: ...

class ClassifyBatchResponse(_message.Message):
    __slots__ = ("results",)
    RESULTS_FIELD_NUMBER: _ClassVar[int]
    results: _containers.RepeatedCompositeFieldContainer[ClassifyResponse]
    def __init__(self, results: _Optional[_Iterable[_Union[ClassifyResponse, _Mapping]]] = ...) -> None: ...

class ModelInfoRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ModelInfoResponse(_message.Message):
    __slots__ = ("model_name", "ready", "device")
    MODEL_NAME_FIELD_NUMBER: _ClassVar[int]
    READY_FIELD_NUMBER: _ClassVar[int]
    DEVICE_FIELD_NUMBER: _ClassVar[int]
    model_name: str
    ready: bool
    device: str
    def __init__(self, model_name: _Optional[str] = ..., ready: bool = ..., device: _Optional[str] = ...) -> None: ...
