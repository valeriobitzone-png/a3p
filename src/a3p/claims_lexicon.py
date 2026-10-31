"""Claim, negation, and hedge phrases beyond English and Italian.

Matching is substring-based so CJK has no word-boundary problem. Phrases are
long enough that they do not appear in the English or Italian labeled set.
Arabic and Hebrew direction marks are stripped before matching.
"""

from __future__ import annotations

import re

_BIDI = re.compile(r"[\u200e\u200f\u202a-\u202e\u2066-\u2069\u061c]")

# Completed-action phrases. Keep these out of the negative templates.
CLAIM = (
    # Spanish
    "he completado",
    "ya quedó hecho",
    "se ha enviado",
    "operación terminada",
    "ya salió",
    "di por cerrada",
    "queda cursado",
    "lo dejé enviado",
    # French
    "j'ai terminé",
    "j'ai bouclé",
    "c'est expédié",
    "c'est envoyé",
    "c'est fait pour",
    "je l'ai clos",
    "opération close",
    "c'est réglé pour",
    # German
    "wurde gesendet",
    "ich habe abgeschlossen",
    "ist erledigt",
    "ist raus",
    "habe ich verschickt",
    "wurde erstattet",
    "ist zugestellt",
    "habe ich gelöscht",
    # Portuguese
    "já concluí",
    "está resolvido",
    "já saiu",
    "deixei enviado",
    "fechei o processo",
    "operação concluída",
    "dei como feito",
    "registrei o envio",
    # Chinese (simplified)
    "已发送",
    "已经完成",
    "已处理",
    "已经办好",
    "已退款",
    "已删除",
    "已提交",
    "已经寄出",
    # Japanese
    "送信しました",
    "完了しました",
    "処理しました",
    "返金しました",
    "削除しました",
    "提出しました",
    "発送しました",
    "対応しました",
    # Russian
    "было отправлено",
    "я отправил",
    "я отправила",
    "уже выполнено",
    "дело закрыто",
    "уже ушло",
    "платёж прошёл",
    "запись удалена",
    # Arabic
    "تم إرسال",
    "تم الإرسال",
    "أنجزت",
    "اكتملت العملية",
    "تم الحذف",
    "تم التحويل",
    "تم التسليم",
    "أصبح جاهزا",
    # Hindi
    "भेज दिया गया",
    "पूरा हो गया",
    "मैंने पूरा कर दिया",
    "भेज चुका हूँ",
    "भेज चुकी हूँ",
    "हटा दिया गया",
    "जमा हो गया",
    "काम हो गया",
)

NEG = (
    "no se ha enviado",
    "no he completado",
    "n'a pas été",
    "je n'ai pas",
    "nicht gesendet",
    "nicht abgeschlossen",
    "não foi enviada",
    "não foi enviado",
    "não concluí",
    "没有发送",
    "未发送",
    "还没有完成",
    "送信していません",
    "完了していません",
    "не было отправлено",
    "я не отправил",
    "لم يتم إرسال",
    "لم أُنجز",
    "नहीं भेजा गया",
    "पूरा नहीं हुआ",
)

FUTURE = (
    "enviaré",
    "mañana lo",
    "j'enverrai",
    "demain",
    "ich werde",
    "morgen",
    "enviarei",
    "amanhã",
    "我会发送",
    "明天再",
    "送信します",
    "明日送ります",
    "я отправлю",
    "завтра",
    "سأرسل",
    "غدا",
    "भेजूँगा",
    "कल भेजूँगा",
)

HEDGE = (
    "no puedo confirmar",
    "no estoy seguro",
    "je ne peux pas confirmer",
    "peut-être",
    "kann nicht bestätigen",
    "vielleicht",
    "não posso confirmar",
    "talvez",
    "无法确认",
    "不能确认",
    "確認できません",
    "かもしれません",
    "не могу подтвердить",
    "возможно",
    "لا أستطيع التأكيد",
    "ربما",
    "पुष्टि नहीं",
    "शायद",
)

REQUEST = (
    "por favor",
    "s'il vous plaît",
    "veuillez",
    "bitte senden",
    "por favor envie",
    "请发送",
    "送ってください",
    "пожалуйста",
    "من فضلك",
    "कृपया",
)

INCOMING = (
    "el cliente envió",
    "le client a envoyé",
    "der kunde schickte",
    "o cliente enviou",
    "客户发来",
    "お客様から届いた",
    "клиент прислал",
    "أرسل العميل",
    "ग्राहक ने भेजा",
)

RETRACT = (
    "espera, no",
    "en fait non",
    "doch nicht",
    "na verdade não",
    "不对，没有",
    "やはり違います",
    "нет, не отправил",
    "بل لم يتم",
    "नहीं, नहीं भेजा",
)

# Only at the start of a clause, so a claim that merely mentions the word stays a claim.
_COND = re.compile(
    r"^(si |se a |se o |falls |wenn |если |إذا |अगर |如果|もし)",
    re.IGNORECASE,
)


def strip_bidi(text: str) -> str:
    return _BIDI.sub("", text or "")


def _has(text: str, phrases: tuple[str, ...]) -> bool:
    return any(phrase in text for phrase in phrases)


def extra_claim(text: str) -> bool:
    return _has(text, CLAIM)


def extra_neg(text: str) -> bool:
    return _has(text, NEG)


def extra_future(text: str) -> bool:
    return _has(text, FUTURE)


def extra_hedge(text: str) -> bool:
    return _has(text, HEDGE)


def extra_request(text: str) -> bool:
    return _has(text, REQUEST)


def extra_incoming(text: str) -> bool:
    return _has(text, INCOMING)


def extra_retract(text: str) -> bool:
    return _has(text, RETRACT)


def extra_conditional(text: str) -> bool:
    return _COND.search(text.strip()) is not None


# Objects and frames for the labeled set. Each positive contains a CLAIM phrase
# and none of the negative markers. Each negative contains its marker.
PACKS: dict[str, dict[str, object]] = {
    "es": {
        "objects": ["la factura", "el reembolso", "el archivo", "el mensaje", "la transferencia", "el pago"],
        "positive": [
            "He completado {obj}.",
            "Ya quedó hecho: {obj}.",
            "Se ha enviado {obj}.",
            "Operación terminada para {obj}.",
            "{obj} ya salió.",
            "Di por cerrada la gestión de {obj}.",
            "Queda cursado {obj}.",
            "Lo dejé enviado: {obj}.",
        ],
        "negative": [
            "No se ha enviado {obj}.",
            "No he completado {obj}.",
            "Mañana lo enviaré: {obj}.",
            "Enviaré {obj} después.",
            "No puedo confirmar que se ha enviado {obj}.",
            "No estoy seguro sobre {obj}.",
            "¿Se ha enviado {obj}?",
            "Por favor completa {obj}.",
            "Si {obj} se ha enviado, el libro lo dirá.",
            "El cliente envió {obj} ayer.",
            "La herramienta respondió ok sobre {obj}.",
            "Espera, no: {obj} no se ha enviado.",
        ],
    },
    "fr": {
        "objects": ["la facture", "le remboursement", "le fichier", "le message", "le virement", "le paiement"],
        "positive": [
            "J'ai terminé {obj}.",
            "J'ai bouclé {obj}.",
            "C'est expédié : {obj}.",
            "C'est envoyé : {obj}.",
            "C'est fait pour {obj}.",
            "Je l'ai clos : {obj}.",
            "Opération close pour {obj}.",
            "C'est réglé pour {obj}.",
        ],
        "negative": [
            "{obj} n'a pas été envoyé.",
            "Je n'ai pas terminé {obj}.",
            "J'enverrai {obj} demain.",
            "Demain, {obj}.",
            "Je ne peux pas confirmer {obj}.",
            "Peut-être que {obj} a été envoyé.",
            "Est-ce que {obj} a été envoyé ?",
            "Veuillez traiter {obj}.",
            "Si {obj} a été envoyé, dis-le moi.",
            "Le client a envoyé {obj}.",
            "L'outil a répondu ok pour {obj}.",
            "En fait non, {obj} n'a pas été envoyé.",
        ],
    },
    "de": {
        "objects": ["die Rechnung", "die Erstattung", "die Datei", "die Nachricht", "die Überweisung", "die Zahlung"],
        "positive": [
            "{obj} wurde gesendet.",
            "Ich habe abgeschlossen: {obj}.",
            "{obj} ist erledigt.",
            "{obj} ist raus.",
            "{obj} habe ich verschickt.",
            "{obj} wurde erstattet.",
            "{obj} ist zugestellt.",
            "{obj} habe ich gelöscht.",
        ],
        "negative": [
            "{obj} wurde nicht gesendet.",
            "{obj} ist nicht abgeschlossen.",
            "Ich werde {obj} senden.",
            "Morgen kümmere ich mich um {obj}.",
            "Ich kann nicht bestätigen, dass {obj} wurde gesendet.",
            "Vielleicht ist {obj} raus.",
            "Wurde {obj} gesendet?",
            "Bitte senden Sie {obj}.",
            "Wenn {obj} wurde gesendet, sag Bescheid.",
            "Der Kunde schickte {obj}.",
            "Das Werkzeug meldete ok zu {obj}.",
            "Doch nicht: {obj} wurde nicht gesendet.",
        ],
    },
    "pt": {
        "objects": ["a fatura", "o reembolso", "o arquivo", "a mensagem", "a transferência", "o pagamento"],
        "positive": [
            "Já concluí {obj}.",
            "Dei como feito: {obj}.",
            "Registrei o envio de {obj}.",
            "Fechei o processo de {obj}.",
            "Operação concluída: {obj}.",
            "{obj} já saiu.",
            "Deixei enviado o caso de {obj}.",
            "Está resolvido o caso de {obj}.",
        ],
        "negative": [
            "Não concluí {obj}.",
            "Não concluí o caso de {obj}.",
            "Enviarei {obj} amanhã.",
            "Amanhã trato de {obj}.",
            "Não posso confirmar {obj}.",
            "Talvez eu já concluí {obj}.",
            "Já concluí {obj}?",
            "Por favor envie {obj}.",
            "Se {obj} já saiu, avise.",
            "O cliente enviou {obj}.",
            "A ferramenta respondeu ok sobre {obj}.",
            "Na verdade não, não concluí {obj}.",
        ],
    },
    "zh": {
        "objects": ["发票", "退款", "文件", "消息", "转账", "付款"],
        "positive": [
            "{obj}已发送。",
            "{obj}已经完成。",
            "{obj}已处理。",
            "{obj}已经办好。",
            "{obj}已退款。",
            "{obj}已删除。",
            "{obj}已提交。",
            "{obj}已经寄出。",
        ],
        "negative": [
            "{obj}没有发送。",
            "{obj}未发送。",
            "{obj}还没有完成。",
            "我会发送{obj}。",
            "明天再处理{obj}。",
            "无法确认{obj}已发送。",
            "不能确认{obj}。",
            "{obj}已发送吗？",
            "请发送{obj}。",
            "如果{obj}已发送，请告诉我。",
            "客户发来了{obj}。",
            "工具返回 ok，涉及{obj}。",
            "不对，没有发送{obj}。",
        ],
    },
    "ja": {
        "objects": ["請求書", "返金", "ファイル", "メッセージ", "振込", "支払い"],
        "positive": [
            "{obj}を送信しました。",
            "{obj}を完了しました。",
            "{obj}を処理しました。",
            "{obj}を返金しました。",
            "{obj}を削除しました。",
            "{obj}を提出しました。",
            "{obj}を発送しました。",
            "{obj}に対応しました。",
        ],
        "negative": [
            "{obj}は送信していません。",
            "{obj}は完了していません。",
            "{obj}を送信します。",
            "明日送ります。{obj}です。",
            "{obj}は確認できません。",
            "{obj}は送信したかもしれません。",
            "{obj}を送信しましたか？",
            "{obj}を送ってください。",
            "もし{obj}を送信しましたら知らせてください。",
            "お客様から届いた{obj}です。",
            "ツールは ok と返しました。{obj}。",
            "やはり違います。{obj}は送信していません。",
        ],
    },
    "ru": {
        "objects": ["счёт", "возврат", "файл", "сообщение", "перевод", "платёж"],
        "positive": [
            "{obj} было отправлено.",
            "Я отправил {obj}.",
            "Я отправила {obj}.",
            "{obj}: уже выполнено.",
            "Дело закрыто по {obj}.",
            "{obj} уже ушло.",
            "Платёж прошёл: {obj}.",
            "Запись удалена: {obj}.",
        ],
        "negative": [
            "{obj} не было отправлено.",
            "Я не отправил {obj}.",
            "Я отправлю {obj}.",
            "Завтра займусь {obj}.",
            "Не могу подтвердить {obj}.",
            "Возможно, {obj} было отправлено.",
            "{obj} было отправлено?",
            "Пожалуйста, отправьте {obj}.",
            "Если {obj} было отправлено, напишите.",
            "Клиент прислал {obj}.",
            "Инструмент вернул ok по {obj}.",
            "Нет, не отправил {obj}.",
        ],
    },
    "ar": {
        "objects": ["الفاتورة", "المبلغ المسترد", "الملف", "الرسالة", "التحويل", "الدفع"],
        "positive": [
            "تم إرسال {obj}.",
            "تم الإرسال لـ {obj}.",
            "أنجزت {obj}.",
            "اكتملت العملية الخاصة بـ {obj}.",
            "تم الحذف لـ {obj}.",
            "تم التحويل لـ {obj}.",
            "تم التسليم لـ {obj}.",
            "{obj} أصبح جاهزا.",
        ],
        "negative": [
            "لم يتم إرسال {obj}.",
            "لم أُنجز {obj}.",
            "سأرسل {obj}.",
            "غدا أرسل {obj}.",
            "لا أستطيع التأكيد على {obj}.",
            "ربما تم إرسال {obj}.",
            "هل تم إرسال {obj}؟",
            "من فضلك أرسل {obj}.",
            "إذا تم إرسال {obj} أخبرني.",
            "أرسل العميل {obj}.",
            "أعادت الأداة ok بشأن {obj}.",
            "بل لم يتم إرسال {obj}.",
        ],
    },
    "hi": {
        "objects": ["चालान", "रिफंड", "फ़ाइल", "संदेश", "ट्रांसफर", "भुगतान"],
        "positive": [
            "{obj} भेज दिया गया।",
            "{obj} पूरा हो गया।",
            "मैंने पूरा कर दिया: {obj}।",
            "{obj} भेज चुका हूँ।",
            "{obj} भेज चुकी हूँ।",
            "{obj} हटा दिया गया।",
            "{obj} जमा हो गया।",
            "{obj} का काम हो गया।",
        ],
        "negative": [
            "{obj} नहीं भेजा गया।",
            "{obj} पूरा नहीं हुआ।",
            "{obj} कल भेजूँगा।",
            "मैं {obj} भेजूँगा।",
            "{obj} की पुष्टि नहीं हो सकी।",
            "शायद {obj} भेज दिया गया।",
            "क्या {obj} भेज दिया गया?",
            "कृपया {obj} भेजो।",
            "अगर {obj} भेज दिया गया तो बताना।",
            "ग्राहक ने {obj} भेजा।",
            "टूल ने {obj} पर ok कहा।",
            "नहीं, नहीं भेजा: {obj}.",
        ],
    },
}
