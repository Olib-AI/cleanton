"""Model twins: the Gather-free export module must equal the trained one."""

import torch

from training.features import FEATURE_COUNT
from training.model import ExportClassifierV2, FileClassifierV2


def test_export_twin_matches_trained_model_bitwise_shapes():
    torch.manual_seed(7)
    trained = FileClassifierV2().eval()
    export = ExportClassifierV2(trained).eval()

    x = torch.zeros(6, FEATURE_COUNT)
    # In-vocab, boundary, and out-of-vocab categorical ids (clamped identically).
    x[:, 0] = torch.tensor([0.0, 1.0, 61.0, 135.0, 500.0, 89.0])
    x[:, 1] = torch.tensor([0.0, 7.0, 120.0, 300.0, 23.0, 110.0])
    x[:, 2] = torch.tensor([0.0, 1.0, 5.0, 120.0, 999.0, 22.0])
    x[:, 3:] = torch.randn(6, FEATURE_COUNT - 3)

    with torch.no_grad():
        expected = trained(x)
        got = export(x)
    assert torch.allclose(expected, got, atol=1e-6), (expected - got).abs().max()


def test_export_twin_shares_parameters_not_copies():
    trained = FileClassifierV2()
    export = ExportClassifierV2(trained)
    assert export.ext_weight is trained.ext_embedding.weight
    assert export.dir_weight is trained.dir_embedding.weight
    assert export.net is trained.net
