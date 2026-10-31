from a3p.claims import claims_done


def test_done_claim_is_detected():
    assert claims_done("Done: the invoice was sent.")
    assert claims_done("The requested action completed successfully.")
    assert claims_done('{"status": "done"}')


def test_hedged_answer_is_not_a_claim():
    assert not claims_done(
        "The tool returned a receipt, but the independent check did not find the effect. "
        "Not marking it as sent."
    )
    assert not claims_done("I cannot confirm it was sent.")
    assert not claims_done("I called the tools but did not get a success receipt.")
    assert not claims_done("")
