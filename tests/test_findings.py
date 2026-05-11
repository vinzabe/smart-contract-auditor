from auditor.findings import Finding, Severity, FindingDB


def _f(detector="reentrancy-eth", contract="Vault", function="withdraw",
       lines=(26,), file_path="contracts/Vault.sol",
       severity=Severity.HIGH, source="slither"):
    return Finding(detector=detector, title=f"x: {detector}", severity=severity,
                   confidence="Medium", contract=contract, function=function,
                   file_path=file_path, lines=list(lines), source=source)


def test_severity_from_str():
    assert Severity.from_str("High") == Severity.HIGH
    assert Severity.from_str("Informational") == Severity.INFO
    assert Severity.from_str("Critical") == Severity.CRITICAL
    assert Severity.from_str("bogus") == Severity.LOW


def test_severity_rank_ordering():
    assert Severity.HIGH.rank() > Severity.MEDIUM.rank() > Severity.LOW.rank()


def test_fingerprint_stable_and_distinguishing():
    a = _f()
    b = _f()
    assert a.fingerprint() == b.fingerprint()
    c = _f(lines=(99,))
    assert a.fingerprint() != c.fingerprint()
    d = _f(function="claimBonus")
    assert a.fingerprint() != d.fingerprint()


def test_findingdb_dedupes():
    db = FindingDB()
    db.add(_f(severity=Severity.MEDIUM))
    db.add(_f(severity=Severity.HIGH, source="mythril"))
    assert len(db.all()) == 1
    # severity promoted to highest seen
    assert db.all()[0].severity == Severity.HIGH
    # sources merged
    fp = db.all()[0].fingerprint()
    assert set(db.sources_for[fp]) == {"slither", "mythril"}


def test_findingdb_separates_distinct():
    db = FindingDB()
    db.add(_f(detector="reentrancy-eth"))
    db.add(_f(detector="tx-origin", function="setOwner", lines=(33,),
               severity=Severity.LOW))
    assert len(db.all()) == 2


def test_findingdb_by_severity_ordering():
    db = FindingDB()
    db.add(_f(detector="x1", severity=Severity.LOW))
    db.add(_f(detector="x2", severity=Severity.CRITICAL, function="f2"))
    db.add(_f(detector="x3", severity=Severity.MEDIUM, function="f3"))
    ordered = db.by_severity()
    assert [o.severity for o in ordered] == [
        Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


def test_findingdb_report_summary():
    db = FindingDB()
    db.add(_f(severity=Severity.HIGH))
    db.add(_f(detector="tx-origin", function="setOwner", lines=(33,),
               severity=Severity.MEDIUM))
    r = db.report()
    assert r["total"] == 2
    assert r["by_severity"]["high"] == 1
    assert r["by_severity"]["medium"] == 1
