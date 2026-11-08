"""Opt-in fold transport adapter for the existing decompile paging implementation."""
from __future__ import annotations

from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from . import DecompileText


def _with_decompile_fold(original):
    def decompile(self, function: Optional[str] = None, address: Any = None,
                  image: Any = None, backend: Optional[str] = None,
                  *, fold: Optional[list[str]] = None) -> DecompileText:
        """Read and join pseudocode pages, optionally requesting presentation folds.

        Existing selectors and backend keep their positional meanings. None omits
        fold; [] explicitly requests no folding. Other lists are type-checked only:
        the server decides which strings it supports. The initial fold is snapshotted
        and copied for each page. Result disclosure attributes come from the first page;
        foldedEvents and its truncation flag do not cover the joined document.
        """
        if fold is None:
            return original(self, function, address, image, backend)

        document = self
        frozen_fold = None

        class FoldRequest:
            # The retained implementation uses only self.command. A per-request
            # proxy leaves the real Document and its command method untouched.
            def command(self, name: str, /, **arguments: Any) -> Any:
                nonlocal frozen_fold
                # Keep original backend validation first; reject bad fold types
                # before any command reaches the document or its transport.
                if frozen_fold is None:
                    if not isinstance(fold, list):
                        raise TypeError("Document.decompile fold must be a list of strings or None")
                    candidate = tuple(fold)
                    if any(not isinstance(kind, str) for kind in candidate):
                        raise TypeError("Document.decompile fold must be a list of strings or None")
                    frozen_fold = candidate
                return document.command(name, **arguments, fold=list(frozen_fold))

        return original(FoldRequest(), function, address, image, backend)

    return decompile
