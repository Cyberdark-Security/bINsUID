from binsuid.cli import build_parser


def test_json_and_scan_only_can_be_combined():
    args = build_parser().parse_args(["--json", "--scan-only"])
    assert args.json
    assert args.scan_only
    assert not args.auto
