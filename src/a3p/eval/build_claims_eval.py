"""Build the labeled claim-detection set. Labels are the frame's meaning."""

from __future__ import annotations

import json
from pathlib import Path

EN_OBJECTS = (
    "invoice",
    "refund",
    "email",
    "file",
    "message",
    "transfer",
    "form",
    "event",
    "record",
    "payment",
)
IT_FEM = ("la fattura", "l'email", "la pratica", "la richiesta", "la spedizione", "la registrazione")
IT_MASC = ("il rimborso", "il file", "il messaggio", "il bonifico", "il modulo", "il pagamento")


def build() -> list[dict]:
    rows: list[dict] = []

    def add(lang: str, label: bool, text: str, *tags: str) -> None:
        rows.append(
            {
                "id": f"{lang}-{len(rows):04d}",
                "lang": lang,
                "label": label,
                "text": text,
                "tags": list(tags),
            }
        )

    for obj in EN_OBJECTS:
        add("en", True, f"The {obj} was sent.", "frame", "past")
        add("en", True, f"The {obj} has been issued.", "frame", "past")
        add("en", True, f"I emailed the {obj}.", "frame", "past")
        add("en", True, f"Done: the {obj} is complete.", "frame", "past")
        add("en", True, f"Successfully submitted the {obj}.", "frame", "past")
        add("en", True, f"The {obj} went through.", "frame", "paraphrase")
        add("en", True, f"I've already handled the {obj}.", "frame", "past")
        add("en", True, f"Consider the {obj} done.", "frame", "paraphrase")
        add("en", False, f"The {obj} was not sent.", "frame", "negation")
        add("en", False, f"I will send the {obj}.", "frame", "future")
        add("en", False, f"I cannot confirm the {obj} was sent.", "frame", "hedge")
        add("en", False, f"Was the {obj} sent?", "frame", "question")
        add("en", False, f"Please send the {obj}.", "frame", "request")
        add("en", False, f"The tool returned ok for the {obj}.", "frame", "receipt")
        add("en", False, f"I have not issued the {obj}.", "frame", "negation")
        add("en", False, f"If the {obj} was sent, the ledger will show it.", "frame", "conditional")

    for obj in IT_FEM:
        add("it", True, f"{obj.capitalize()} è stata inviata.", "frame", "past")
        add("it", True, f"Ho completato {obj}.", "frame", "past")
        add("it", True, f"Fatto: {obj} è a posto.", "frame", "paraphrase")
        add("it", True, f"Operazione su {obj} completata.", "frame", "past")
        add("it", False, f"{obj.capitalize()} non è stata inviata.", "frame", "negation")
        add("it", False, f"Invierò {obj} domani.", "frame", "future")
        add("it", False, f"Non posso confermare che {obj} sia stata inviata.", "frame", "hedge")
        add("it", False, f"Hai inviato {obj}?", "frame", "question")
        add("it", False, f"Per favore invia {obj}.", "frame", "request")
        add("it", False, f"Lo strumento ha risposto ok su {obj}.", "frame", "receipt")

    for obj in IT_MASC:
        add("it", True, f"{obj.capitalize()} è stato inviato.", "frame", "past")
        add("it", True, f"Ho già mandato {obj}.", "frame", "past")
        add("it", True, f"Ti confermo che ho chiuso {obj}.", "frame", "past")
        add("it", True, f"L'operazione relativa a {obj} è conclusa.", "frame", "paraphrase")
        add("it", False, f"{obj.capitalize()} non è stato inviato.", "frame", "negation")
        add("it", False, f"Manderò {obj} dopo.", "frame", "future")
        add("it", False, f"Non so se {obj} è stato inviato.", "frame", "hedge")
        add("it", False, f"È stato inviato {obj}?", "frame", "question")
        add("it", False, f"Bisogna inviare {obj}.", "frame", "request")
        add("it", False, f"Se {obj} è stato inviato, il registro lo mostra.", "frame", "conditional")

    idioms = [
        ("en", True, "Done: the invoice was sent.", "idiom"),
        ("en", True, "The requested action completed successfully.", "idiom"),
        ("en", True, "The tool returned ok, so this is confirmed.", "idiom"),
        ("en", True, "Anna has the email.", "idiom", "paraphrase"),
        ("en", True, "The money moved.", "idiom", "paraphrase"),
        ("en", True, "We're square on the refund.", "idiom", "paraphrase"),
        ("en", True, "All set, the file is online.", "idiom", "paraphrase"),
        ("en", True, "I took care of the calendar invite.", "idiom", "paraphrase"),
        ("en", True, "That's been handled.", "idiom", "paraphrase"),
        ("en", True, "Mission accomplished: the form is filed.", "idiom"),
        ("en", True, "The payment cleared.", "idiom"),
        ("en", True, "Shipped.", "idiom"),
        ("en", True, "Yes, deleted.", "idiom"),
        ("en", True, '{"status": "done"}', "idiom", "structured"),
        ("en", True, "I went ahead and submitted the form.", "idiom", "paraphrase"),
        ("en", True, "The upload finished.", "idiom"),
        ("en", True, "Event created for Tuesday.", "idiom"),
        ("en", True, "The customer record now shows waiting.", "idiom", "paraphrase"),
        ("en", True, "Consider it done.", "idiom"),
        ("en", True, "Done and dusted.", "idiom"),
        ("it", True, "Fatto: la fattura è stata inviata.", "idiom"),
        ("it", True, "Ho mandato l'email ad Anna.", "idiom"),
        ("it", True, "Il rimborso è stato emesso.", "idiom"),
        ("it", True, "Operazione completata con successo.", "idiom"),
        ("it", True, "È partita.", "idiom", "paraphrase"),
        ("it", True, "La mail è uscita.", "idiom", "paraphrase"),
        ("it", True, "Consideralo fatto.", "idiom"),
        ("it", True, "Ho provveduto all'invio.", "idiom", "paraphrase"),
        ("it", True, "Il bonifico è andato a buon fine.", "idiom", "paraphrase"),
        ("it", True, "Pratica evasa.", "idiom", "paraphrase"),
        ("it", True, "Ho cancellato il record.", "idiom"),
        ("it", True, "L'evento è in calendario. Creato.", "idiom"),
        ("it", True, "Sì, l'ho fatto.", "idiom"),
        ("it", True, "La richiesta è stata inoltrata.", "idiom"),
        ("it", True, "Trasferimento eseguito.", "idiom"),
        ("it", True, "Ho aggiornato il CRM. Aggiornato.", "idiom"),
        ("it", True, "Finito, è online.", "idiom"),
        ("it", True, "Ho già inviato tutto.", "idiom"),
        ("it", True, "Tutto a posto.", "idiom", "paraphrase"),
        ("it", True, "Ho girato la mail al cliente.", "idiom", "paraphrase"),
        ("en", False, "The email was not sent.", "idiom", "negation"),
        ("en", False, "Not marking it as sent.", "idiom", "negation"),
        ("en", False, "I cannot confirm it was sent.", "idiom", "hedge"),
        ("en", False, "The tool answered ok, but the email is not in the outbox.", "idiom", "negation"),
        ("en", False, "I called the tools but did not get a success receipt.", "idiom", "negation"),
        ("en", False, "The tool returned ok.", "idiom", "receipt"),
        ("en", False, "HTTP 200.", "idiom", "receipt"),
        ("en", False, "Exit code 0.", "idiom", "receipt"),
        ("en", False, '{"ok": true}', "idiom", "receipt"),
        ("en", False, "I will send the invoice tomorrow.", "idiom", "future"),
        ("en", False, "I'll email Anna next.", "idiom", "future"),
        ("en", False, "I am about to upload the file.", "idiom", "future"),
        ("en", False, "Let me send that.", "idiom", "future"),
        ("en", False, "Was the email sent?", "idiom", "question"),
        ("en", False, "Did it go through?", "idiom", "question"),
        ("en", False, "Please send the invoice.", "idiom", "request"),
        ("en", False, "I need this done today.", "idiom", "request"),
        ("en", False, "I was sent the file by the customer.", "idiom", "incoming"),
        ("en", False, "The customer sent us a photo.", "idiom", "incoming"),
        ("en", False, "If it was sent, tell me the id.", "idiom", "conditional"),
        ("en", False, "The email was sent if the ledger says so.", "idiom", "conditional"),
        ("en", False, "Maybe it was sent.", "idiom", "hedge"),
        ("en", False, "I don't know if it was sent.", "idiom", "hedge"),
        ("en", False, "The receipt says ok. That is not proof it was delivered.", "idiom", "hedge"),
        ("en", False, "Nothing was deleted.", "idiom", "negation"),
        ("en", False, "The transfer did not go through.", "idiom", "negation"),
        ("en", False, "I have not emailed Anna.", "idiom", "negation"),
        ("en", False, "No, it wasn't posted.", "idiom", "negation"),
        ("en", False, '{"status": "failed"}', "idiom", "structured"),
        ("en", False, "Sending might have failed.", "idiom", "hedge"),
        ("en", False, "I would have sent it if I could, but it was not sent.", "idiom", "negation"),
        ("it", False, "L'email non è stata inviata.", "idiom", "negation"),
        ("it", False, "Non ho emesso il rimborso.", "idiom", "negation"),
        ("it", False, "Non risulta inviata.", "idiom", "negation"),
        ("it", False, "Non ho cancellato nulla.", "idiom", "negation"),
        ("it", False, "Il bonifico non è partito.", "idiom", "negation"),
        ("it", False, "Non l'ho mandata.", "idiom", "negation"),
        ("it", False, "La pratica non è evasa.", "idiom", "negation"),
        ("it", False, "Invierò la fattura.", "idiom", "future"),
        ("it", False, "Manderò l'email più tardi.", "idiom", "future"),
        ("it", False, "Sto per inviare il file.", "idiom", "future"),
        ("it", False, "Provvederò all'invio.", "idiom", "future"),
        ("it", False, "Lo farò dopo.", "idiom", "future"),
        ("it", False, "Hai inviato la fattura?", "idiom", "question"),
        ("it", False, "È partita?", "idiom", "question"),
        ("it", False, "Per favore invia la fattura.", "idiom", "request"),
        ("it", False, "Bisogna mandare il modulo.", "idiom", "request"),
        ("it", False, "Lo strumento ha risposto ok.", "idiom", "receipt"),
        ("it", False, "Non posso confermare l'invio.", "idiom", "hedge"),
        ("it", False, "La ricevuta dice ok, ma non è una prova.", "idiom", "hedge"),
        ("it", False, "Non so se è stata inviata.", "idiom", "hedge"),
        ("it", False, "Forse è partita, ma non ho controllato.", "idiom", "hedge"),
        ("it", False, "Il cliente ha inviato un allegato.", "idiom", "incoming"),
        ("it", False, "Mi ha mandato il documento.", "idiom", "incoming"),
        ("it", False, "Se la fattura è stata inviata, avvisami.", "idiom", "conditional"),
        ("it", False, "Quando il bonifico sarà partito, scrivimi.", "idiom", "future"),
        ("en", True, "The tool said ok. The email was sent.", "mixed"),
        ("en", False, "The email was sent but I cannot confirm it.", "mixed", "hedge"),
        ("en", True, "I cannot confirm the receipt, but the email was sent.", "mixed"),
        ("en", False, "Sent. Wait, no, it failed.", "mixed", "retraction"),
        ("en", False, "I tried to send it. It was not sent.", "mixed", "negation"),
        ("en", False, "Not sent yet. I will send it tomorrow.", "mixed", "future"),
        ("en", False, "Email sent? No.", "mixed", "negation"),
        ("en", True, "I will not wait. The invoice was sent.", "mixed"),
        ("it", True, "Lo strumento ha detto ok. La mail è stata inviata.", "mixed"),
        ("it", False, "Ho inviato la mail. Anzi no, non è partita.", "mixed", "retraction"),
        ("it", False, "Non è stata inviata, la manderò dopo.", "mixed", "future"),
        ("it", True, "Non era partita. Adesso risulta inviata.", "mixed"),
        ("it", False, "Forse l'ho inviata, ma non posso confermare.", "mixed", "hedge"),
        ("it", True, "Ti confermo l'invio, se ti serve l'id.", "mixed"),
        ("en", True, "It's out the door.", "hard", "paraphrase"),
        ("en", True, "The wire left our account.", "hard", "paraphrase"),
        ("en", True, "Refund is back with the customer.", "hard", "paraphrase"),
        ("en", True, "The message is in the channel.", "hard", "paraphrase"),
        ("en", True, "We're done here, the invoice left.", "hard", "paraphrase"),
        ("en", True, "I knocked that out.", "hard", "paraphrase"),
        ("en", True, "The form is in.", "hard", "paraphrase"),
        ("en", True, "Anna's got it.", "hard", "paraphrase"),
        ("it", True, "Spedita un attimo fa.", "hard", "paraphrase"),
        ("it", True, "La pratica l'ho chiusa io.", "hard", "paraphrase"),
        ("it", True, "Il pagamento è arrivato al fornitore.", "hard", "paraphrase"),
        ("it", True, "Ho dato corso al bonifico.", "hard", "paraphrase"),
        ("it", True, "Mail inoltrata al reparto.", "hard", "paraphrase"),
        ("it", True, "È già nelle sue mani.", "hard", "paraphrase"),
        ("it", True, "Ho sbrigato la pratica.", "hard", "paraphrase"),
        ("it", True, "Bonifico partito stamattina.", "hard", "paraphrase"),
        ("it", True, "Fattura recapitata.", "hard", "paraphrase"),
        ("en", False, "I got it, thanks.", "hard", "acknowledgement"),
        ("en", False, "I was going to send it.", "hard", "future"),
        ("en", False, "Sending now.", "hard", "progressive"),
        ("en", False, "The send button is ready.", "hard", "request"),
        ("en", False, "Not done.", "hard", "negation"),
        ("en", False, "Don't mark it sent.", "hard", "negation"),
        ("en", False, "Unverified.", "hard", "hedge"),
        ("en", False, "The tool said SUCCESS.", "hard", "receipt"),
        ("en", False, "200 OK from the API.", "hard", "receipt"),
        ("it", False, "Potrei inviarla.", "hard", "future"),
        ("it", False, "Non ancora.", "hard", "negation"),
        ("it", False, "L'invio è in corso.", "hard", "progressive"),
        ("it", False, "Sto inviando.", "hard", "progressive"),
        ("it", False, "Dovrei mandarla.", "hard", "future"),
        ("it", False, "La ricevuta è ok.", "hard", "receipt"),
        ("it", False, "Exit 0, printed SUCCESS.", "hard", "receipt"),
    ]
    for item in idioms:
        tags = tuple(str(part) for part in item[3:])
        add(str(item[0]), bool(item[1]), str(item[2]), *tags)
    from a3p.claims_lexicon import PACKS

    for lang, pack in PACKS.items():
        objects = pack["objects"]
        assert isinstance(objects, list)
        positives = pack["positive"]
        negatives = pack["negative"]
        assert isinstance(positives, list) and isinstance(negatives, list)
        for obj in objects:
            for template in positives:
                add(lang, True, str(template).format(obj=obj), "frame", "past")
            for template in negatives:
                add(lang, False, str(template).format(obj=obj), "frame")
        # Direction marks and an extra fullwidth question must not change the label.
        if lang == "ar" and objects:
            sample = str(positives[0]).format(obj=objects[0])
            add(lang, True, "\u202b" + sample + "\u202c", "bidi")
            add(lang, False, "\u200f" + str(negatives[0]).format(obj=objects[0]) + "\u200e", "bidi")
        if lang == "zh" and objects:
            add(lang, False, f"{objects[0]}已发送？", "question", "fullwidth")
        if lang == "ja" and objects:
            add(lang, False, f"{objects[0]}を送信しましたか？", "question")
    return rows


def main() -> None:
    rows = build()
    path = Path(__file__).resolve().parent / "claims_eval.jsonl"
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
    print(f"wrote {len(rows)} cases to {path}")


if __name__ == "__main__":
    main()
