<?php
/**
 * TecNexis Fiber Connect – Kontaktformular-Versand
 * Liegt auf dem Webspace im selben Ordner wie index.html.
 * Empfänger: info@tecnexis.de
 */
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

const MAIL_TO   = 'info@tecnexis.de';
// Absender muss zu Ihrer Domain gehören, sonst lehnen Mailserver die Nachricht oft ab.
const MAIL_FROM = 'no-reply@tecnexis.de';

function respond(int $status, array $data): never
{
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

function clean(mixed $value, int $max): string
{
    $v = str_replace(["\r", "\n", "\0"], ' ', trim((string) $value));
    return mb_substr($v, 0, $max);
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    respond(405, ['ok' => false, 'error' => 'method_not_allowed']);
}

// Honeypot: Bots füllen das versteckte Feld aus. Still verwerfen.
if (!empty($_POST['web'])) {
    respond(200, ['ok' => true]);
}

$name    = clean($_POST['name'] ?? '', 100);
$firma   = clean($_POST['firma'] ?? '', 120);
$mail    = clean($_POST['mail'] ?? '', 160);
$tel     = clean($_POST['tel'] ?? '', 40);
$betreff = clean($_POST['betreff'] ?? '', 150);
$msg     = mb_substr(str_replace("\0", '', trim((string) ($_POST['msg'] ?? ''))), 0, 5000);
$dsgvo   = !empty($_POST['dsgvo']);

$errors = [];
if (mb_strlen($name) < 2)                          $errors[] = 'name';
if (!filter_var($mail, FILTER_VALIDATE_EMAIL))     $errors[] = 'mail';
if ($tel !== '' && !preg_match('/^[+()\d\s\/-]{6,}$/', $tel)) $errors[] = 'tel';
if (mb_strlen($betreff) < 3)                       $errors[] = 'betreff';
if (mb_strlen($msg) < 10)                          $errors[] = 'msg';
if (!$dsgvo)                                       $errors[] = 'dsgvo';
if ($errors) {
    respond(422, ['ok' => false, 'error' => 'validation', 'fields' => $errors]);
}

// Einfache Mengenbegrenzung: eine Anfrage pro IP alle 30 Sekunden.
$ip   = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$lock = sys_get_temp_dir() . '/tecnexis_form_' . hash('sha256', $ip);
if (is_file($lock) && (time() - (int) filemtime($lock)) < 30) {
    respond(429, ['ok' => false, 'error' => 'too_many_requests']);
}
@touch($lock);

$subject = '=?UTF-8?B?' . base64_encode('Website-Anfrage: ' . $betreff) . '?=';

$body  = "Neue Anfrage über die Website tecnexis.de\n";
$body .= "----------------------------------------\n";
$body .= "Name:         $name\n";
$body .= "Unternehmen:  " . ($firma !== '' ? $firma : '-') . "\n";
$body .= "E-Mail:       $mail\n";
$body .= "Telefon:      " . ($tel !== '' ? $tel : '-') . "\n";
$body .= "Betreff:      $betreff\n";
$body .= "----------------------------------------\n\n";
$body .= $msg . "\n\n";
$body .= "----------------------------------------\n";
$body .= 'Gesendet am ' . date('d.m.Y H:i') . " Uhr\n";

$headers = [
    'From'         => 'TecNexis Website <' . MAIL_FROM . '>',
    'Reply-To'     => $mail,
    'MIME-Version' => '1.0',
    'Content-Type' => 'text/plain; charset=UTF-8',
    'Content-Transfer-Encoding' => '8bit',
    'X-Mailer'     => 'TecNexis-Kontaktformular',
];

$sent = mail(MAIL_TO, $subject, $body, $headers);

if (!$sent) {
    @unlink($lock);
    respond(500, ['ok' => false, 'error' => 'mail_failed']);
}

respond(200, ['ok' => true]);
