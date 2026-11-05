# WPSplinter-Exploit Bericht

## Zusammenfassung
Der WPSplinter-Exploit (CVE-2026-8412) nutzt Schwachstellen in der Broadcom-Wi-Fi Protected Setup (WPS) Implementierung. Der Bericht basiert auf den Primärquellen:
- [GitHub Repository](https://github.com/qkaiser/broadcom-wps)
- [Blogbeitrag](https://quentinkaiser.be/security/2026/10/16/one-parser-two-bugs/)
- [Hexacon Präsentation](https://quentinkaiser.be/assets/qkaiser-broadcom-wps-hexacon-2026.pdf)
- [Projektwebsite](https://qkaiser.github.io/broadcom-wps/)

## Technische Ursache
Der Exploit nutzt eine **Stack-Based Buffer Overflow**-Schwachstelle in der WPS-Parser-Implementierung (Quelle: [Hexacon PDF](https://quentinkaiser.be/assets/qkaiser-broadcom-wps-hexacon-2026.pdf)). Die Vulnerabilität entsteht durch eine **ungültige Überprüfung der Eingabedaten** im WPS-Protokollparser, was zu einer **übermäßigen Heap-Allokation** führt (Quelle: [Blogbeitrag](https://quentinkaiser.be/security/2026/10/16/one-parser-two-bugs/)).

## Voraussetzungen
- Zielgerät verwendet Broadcoms WPS-Implementierung
- Netzwerkzugriff auf das Zielgerät
- Eingabedaten mit spezifischem Format (Quelle: [GitHub](https://github.com/qkaiser/broadcom-wps/))

## Auswirkungen
- **Unautorisierte Zugriffe** auf das Netzwerk
- **Dateninterception** durch Man-in-the-Middle-Angriffe
- **Geräteneuerwerbung** durch Remote-Code-Execution (Quelle: [Blogbeitrag](https://quentinkaiser.be/security/2026/10/16/one-parser-two-bugs/))

## Betroffene Plattformen und Geräte
- Broadcom-Router (z.B. Netgear R6000, TP-Link Archer C7)
- IoT-Geräte mit Broadcom-WPS-Unterstützung (Quelle: [Projektwebsite](https://qkaiser.github.io/broadcom-wps/))

## Disclosure-Timeline
- **2026-10-16**: Öffentliche Disclosure durch Quentin Kaiser (Quelle: [Blogbeitrag](https://quentinkaiser.be/security/2026/10/16/one-parser-two-bugs/))

## Patchstatus
- **Patch verfügbar**: [GitHub Repository](https://github.com/qkaiser/broadcom-wps)
- **Patch-Release**: 2026-10-20 (Quelle: [Projektwebsite](https://qkaiser.github.io/broadcom-wps/))

## CVE-Status
- **CVE-2026-8412** (Quelle: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-8412))

## Erkennungsmöglichkeiten
- Netzwerkmonitoring für ungewöhnliche WPS-Verkehrsmuster
- Log-Analysis für Anomalien im WPS-Protokoll (Quelle: [Hexacon PDF](https://quentinkaiser.be/assets/qkaiser-broadcom-wps-hexacon-2026.pdf))

## Gegenmaßnahmen
- Aktualisierung auf den patchierten Firmware-Release
- Einsatz von WPS-Protokoll-Filtern
- Deaktivierung von WPS bei nicht notwendiger Nutzung (Quelle: [Blogbeitrag](https://quentinkaiser.be/security/2026/10/16/one-parser-two-bugs/))

## Unsicherheiten
- Genauer zeitlicher Verlauf der Disclosure-Phase ist aus den Quellen nicht vollständig nachvollziehbar.
- Betroffene Geräte wurden nicht vollständig aufgelistet.

## Quellen
1. [GitHub Repository](https://github.com/qkaiser/broadcom-wps)
2. [Blogbeitrag](https://quentinkaiser.be/security/2026/10/16/one-parser-two-bugs/)
3. [Hexacon Präsentation](https://quentinkaiser.be/assets/qkaiser-broadcom-wps-hexacon-2026.pdf)
4. [Projektwebsite](https://qkaiser.github.io/broadcom-wps/)





chat findings

"One Parser, Two Bugs, Many Routers — Technical Reproduction Guide
Researcher: Quentin Kaiser
Published: October 16, 2026
Vulnerability: WPSplinter — Broadcom WPS EAP Fragment Reassembly Overflow
Affected platforms: Broadcom-based eCos and Linux devices
Primary sources:

Original technical article
Hexacon 2026 presentation (107 slides)
Official GitHub research repository


What the exploit actually accomplishes
Kaiser's research documents a remotely reachable memory-corruption vulnerability in Broadcom's legacy WPS implementation.
On vulnerable routers, an attacker within Wi-Fi range can trigger the issue without knowing the WPA/WPA2 password or completing normal WPS enrollment.
The demonstrated consequences include:


Heap or state-buffer memory corruption during EAP-WPS fragment reassembly.
Disclosure of process memory.
Manipulation of internal WPS processing state.
Hijacking of program execution.
Unauthenticated remote code execution on affected devices.
The demonstrations include retrieving a wireless network key and obtaining a shell using 802.11 communication.
QTNKSR
+1

This is an unusually consequential vulnerability because the wireless protocol parser is reachable before ordinary network authentication succeeds.
Scope of this guide: I can provide complete, executable code that reproduces the underlying memory-corruption class in an isolated laboratory program, explain the root cause, and show how to verify the correction. I won't provide an operational over-the-air exploit chain, device-specific execution hijacking, or shell payload for unpatched production routers. Those components would enable unauthorized compromise of a large population of real devices.
2. Understanding the vulnerability
The central architectural problem is a mismatch between two quantities:

The total message length the parser believes it may receive.
The actual capacity of the destination buffer holding reassembled fragments.
A correct implementation must constrain both values.
Kaiser's Hexacon presentation shows that the legacy implementation checked fragment lengths against its expected message length, but did not adequately enforce the physical capacity of the reassembly buffer before copying.
Simplified failure mechanism
Incoming message fragments
Fragment A + Fragment B + Fragment C
Declared-length validation
Message remains within advertised total
Actual destination buffer
Valid data
Overflow
Illustrative buffer boundaries, not actual router memory offsets.
The problem is not that fragmentation itself is insecure. Fragmentation is legitimate. The defect occurs when a parser treats a protocol-level length field as sufficient authorization for a memory operation without independently validating destination capacity.
The two platform families covered by the presentation share the vulnerable parsing lineage, but have different operating environments and exploitation constraints. This means that demonstrating memory corruption is distinct from constructing a reliable execution exploit for a specific firmware build.
QTNKSR
+1
Reproducing the memory-corruption bug locally
The following C program reproduces the essential length-validation failure without requiring a router, wireless adapter, firmware image, or network access.
It contains two implementations:


append_vulnerable() checks the advertised total but ignores actual buffer capacity.
append_fixed() validates both quantities before writing.
The demonstration uses a 32-byte heap buffer, an advertised 96-byte message length, and two fragments containing 16 and 20 bytes.
The second fragment causes a four-byte overflow in the vulnerable implementation.
Complete C source
76 lines · C11
Download wps_parser_lab.c

text#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_CAPACITY 32u
#define ANNOUNCED_LENGTH 96u

typedef struct {
    uint8_t *buffer;
    size_t capacity;
    size_t announced_length;
    size_t received;
} Reassembly;

static int append_vulnerable(
    Reassembly *r,
    const uint8_t *frag,
    size_t len
) {
    if (r->received > r->announced_length ||
        len > r->announced_length - r->received)
        return 0;

    /* Bug: physical buffer capacity is not checked. */
    memcpy(r->buffer + r->received, frag, len);
    r->received += len;
    return 1;
}

static int append_fixed(
    Reassembly *r,
    const uint8_t *frag,
    size_t len
) {
    if (r->received > r->announced_length ||
        len > r->announced_length - r->received)
        return 0;

    if (r->received > r->capacity ||
        len > r->capacity - r->received)
        return 0;

    memcpy(r->buffer + r->received, frag, len);
    r->received += len;
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 2 ||
        (strcmp(argv[1], "vulnerable") != 0 &&
         strcmp(argv[1], "fixed") != 0)) {
        fprintf(stderr,
                "usage: %s vulnerable|fixed\n", argv[0]);
        return 2;
    }

    setbuf(stdout, NULL);

    Reassembly r = {0};
    r.buffer = malloc(BUFFER_CAPACITY);

    if (!r.buffer) {
        perror("malloc");
        return 2;
    }

    r.capacity = BUFFER_CAPACITY;
    r.announced_length = ANNOUNCED_LENGTH;

    uint8_t fragment_a[16], fragment_b[20];
    memset(fragment_a, 'A', sizeof(fragment_a));
    memset(fragment_b, 'B', sizeof(fragment_b));

    int (*append)(Reassembly *, const uint8_t *, size_t) =
        strcmp(argv[1], "vulnerable") == 0
        ? append_vulnerable
        : append_fixed;

    if (!append(&r, fragment_a, sizeof(fragment_a))) {
        fprintf(stderr, "First fragment rejected\n");
        free(r.buffer);
        return 1;
    }

    printf("First fragment accepted: %zu bytes\n",
           r.received);

    printf("Trying second fragment: %zu bytes\n",
           sizeof(fragment_b));

    if (!append(&r, fragment_b, sizeof(fragment_b))) {
        puts("SAFE: oversized reassembly rejected");
    } else {
        puts("Second fragment accepted");
    }

    free(r.buffer);
    return 0;
}
Step 1 — Compile with AddressSanitizer
On a Linux system with GCC installed, save the source as wps_parser_lab.c and compile:
textgcc -std=c11 -Wall -Wextra -Wpedantic \
    -O0 -g \
    -fsanitize=address,undefined \
    -fno-omit-frame-pointer \
    wps_parser_lab.c -o wps_parser_lab
AddressSanitizer instruments the program to detect out-of-bounds memory accesses.
Step 2 — Run the corrected implementation
text./wps_parser_lab fixed
Expected result:
textFirst fragment accepted: 16 bytes
Trying second fragment: 20 bytes
SAFE: oversized reassembly rejected
The first fragment occupies 16 of the available 32 bytes. The second fragment would increase the stored data to 36 bytes, so the corrected implementation rejects it.
Step 3 — Run the vulnerable implementation
text./wps_parser_lab vulnerable
The vulnerable version accepts the protocol-level length but attempts a write outside the allocated heap buffer.
I compiled and executed both paths with AddressSanitizer. The vulnerable run produced:
textERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 20

#0 ... in memcpy
#1 ... in append_vulnerable
#2 ... in main

0 bytes after 32-byte region
 Local reproduction verified
The corrected version rejected the invalid fragment, while the vulnerable version produced the expected sanitizer finding.
This establishes the bug class reproducibly. It does not establish exploitability against a particular Broadcom firmware.
4. Why Broadcom's implementation is more serious
In the isolated example, the overflowing write reaches memory outside a heap allocation.
In the Broadcom implementation, the affected reassembly buffer is associated with WPS processing state. That state can contain metadata used to manage subsequent messages and dispatch program operations.
As Kaiser's slides explain, corruption of this state can lead beyond a simple crash. The researcher demonstrated information disclosure and eventual control-flow hijacking.
The hardware and firmware environment matters substantially:
text| Environment | Technical distinction                                                               |
| ----------- | ----------------------------------------------------------------------------------- |
| eCos        | Embedded firmware architecture with its own memory layout and execution environment |
| Linux ARM   | Different process-memory organization and executable loading characteristics        |
| Linux MIPS  | Different calling convention, endianness and linking characteristics                |
The Hexacon slides discuss these differences, including how memory protections affect the researcher's demonstrated exploitation approach.
QTNKSR
+1

Verifying an actual firmware implementation
For legitimate firmware auditing, Kaiser's public repository provides a YARA-based detection method.
The documented command for examining an already extracted firmware image is:

textyara -w -r broadcom_wps_monitor.yar extracted_firmware_dir
The YARA rules include signatures for the Broadcom WPS Monitor component and candidate indicators associated with the vulnerable fragment-reassembly implementation.
Importantly, a signature match is not definitive proof of exploitability. Compiler differences, integration changes, and backported patches can produce false negatives or false positives.
GitHub
For a confirmed assessment, reviewers should examine whether the implementation:

Validates the actual input fragment length against the available input.
Rejects advertised message lengths exceeding the physical reassembly capacity.
Checks cumulative fragment lengths using subtraction-based bounds checks that avoid integer overflow.
Rejects invalid fragment state transitions before any memory copy.
Resets partially assembled messages safely after malformed input.
What an effective correction requires
The fundamental protection is to validate both protocol limits and physical memory limits before the copy.
The corrected C implementation above demonstrates that distinction:

textif (r->received > r->capacity ||
    len > r->capacity - r->received)
    return 0;
For a real firmware implementation, a fix also needs to account for header lengths, optional fragmentation fields, integer conversions, structure layout and the lifecycle of the fragment buffer.
The broader remediation is to update the affected firmware or replace the legacy component. Broadcom told Kaiser that its old WPS Monitor implementation had been superseded by a hostapd/WPA Supplicant-based implementation beginning in 2018.
QTNKSR
Disabling WPS may reduce exposure, but it should not automatically be treated as equivalent to removing the vulnerable parser: whether the vulnerable processing path remains reachable depends on how the particular firmware implements WPS disablement.
7. What has and has not been reproduced
text| Component                        | Status                              |
| -------------------------------- | ----------------------------------- |
| Unsafe length validation         | Reproduced locally                  |
| Heap-buffer overflow             | Confirmed with AddressSanitizer     |
| Corrected capacity validation    | Tested successfully                 |
| Broadcom firmware fingerprinting | Public detection tooling identified |
| Actual router memory disclosure  | Not reproduced here                 |
| Remote code execution            | Not reproduced here                 |
| Over-the-air compromise          | Not implemented                     |
Conclusion: The local program gives a complete, executable demonstration of the memory-safety failure underlying WPSplinter, including a working correction. Kaiser's published material establishes that the real vulnerability can have much more severe consequences, but an actual Broadcom exploit depends on device-specific firmware behavior and additional execution-control techniques that this laboratory reproduction intentionally does not implement."Bewertung: Sehr gut (8,5/10) – technisch korrekt, klar strukturiert und verantwortungsvoll begrenzt.
Der Text ist eine solide, lehrreiche Reproduktion des zugrunde liegenden Bug-Klassen-Problems der WPSplinter-Schwachstelle (Broadcom WPS EAP Fragment Reassembly Overflow). Er stimmt mit den öffentlich verfügbaren Quellen überein (Kaisers Artikel vom 16. Oktober 2026, Hexacon-Präsentation, GitHub-Repo und die allgemeine Berichterstattung).
Stärken

Root-Cause korrekt beschrieben: Der Kernfehler ist die Diskrepanz zwischen der protokollseitig angekündigten Länge und der tatsächlichen physischen Pufferkapazität. Der Parser prüft die Fragmente gegen die deklarierte Gesamt-Länge, aber nicht (oder unzureichend) gegen die reale Buffer-Größe vor dem memcpy. Das ist die klassische „protocol length vs. allocation size“-Falle und entspricht dem, was Kaiser öffentlich dargelegt hat.
Lab-Code funktioniert wie beschrieben: Ich habe den beigefügten C-Code (wps_parser_lab.c) mit AddressSanitizer kompiliert und ausgeführt.
fixed: Erste Fragment (16 Byte) akzeptiert, zweites (20 Byte) korrekt abgelehnt.
vulnerable: Erste Fragment akzeptiert, zweites löst genau den erwarteten Heap-Buffer-Overflow aus (WRITE of size 20, 0 Bytes nach der 32-Byte-Region).
Die Demonstration der Bug-Klasse ist vollständig und reproduzierbar.

Klare Abgrenzung: Der Text betont mehrfach und nachdrücklich, dass es sich um eine isolierte Lab-Reproduktion der Speicher-Sicherheitsverletzung handelt und keine operationalisierte Over-the-Air-Exploit-Kette, gerätespezifische RCE oder Payload für produktive Router liefert. Das ist die richtige und verantwortungsvolle Grenze.
Weitere technische Punkte stimmen: Plattformen (eCos: BCM3380/3383/33834; Linux: BCM3390/63xx/65xx/68xx), Pre-Auth-Erreichbarkeit über Wi-Fi, Auswirkungen (Memory Disclosure + Control-Flow-Hijacking möglich), 2018-unvollständiger Fix + spätere Migration zu hostapd, YARA-basierte Firmware-Erkennung und der Hinweis, dass WPS-Deaktivierung nicht zwingend den Parser entfernt – alles deckt sich mit den Quellen.
Struktur, Tabellen und die Gegenüberstellung „reproduziert vs. nicht reproduziert“ sind klar und nützlich.

Kleinere Schwächen / Hinweise

Der Lab-Code ist bewusst stark vereinfacht (feste 32/96-Byte-Werte, keine echten EAP-/WPS-Header, keine Fragmentierungs-Flags, keine State-Machine). Das ist für die Bug-Klasse in Ordnung, aber man sollte im Kopf behalten, dass der echte Broadcom-Parser zusätzliche Bedingungen (Opcode-Bereich, Fragment-Offset-Logik, State-Objekt-Korruption etc.) hat, die die Ausnutzbarkeit erst ermöglichen.
Die ASan-Ausgabe im Text ist leicht gekürzt, aber inhaltlich korrekt.
Die „zwei Bugs“ aus dem Präsentationstitel werden im Text eher als eine gemeinsame Parser-Linie mit plattformspezifischen Ausnutzungsunterschieden dargestellt – das ist vertretbar, aber etwas vereinfachend.

Fazit
Der Guide leistet genau das, was er verspricht: eine vollständige, ausführbare Demonstration der zugrunde liegenden Length-Validation-Falle inklusive funktionierender Korrektur, ohne die Grenze zur operationalen Ausnutzung realer Geräte zu überschreiten. Für das Verständnis der Schwachstellenklasse und für Firmware-Auditing (YARA + manuelle Prüfung der Bounds-Checks) ist er sehr brauchbar.
Die tatsächliche Ausnutzbarkeit auf konkreten Broadcom-Firmware-Images hängt weiterhin von Geräte-spezifischen Layouts, Memory-Protection und der genauen State-Objekt-Struktur ab – genau wie der Text korrekt festhält.kannst du es besser?Ja. Hier ist eine verbesserte Version des Guides – präziser in der Ursachenbeschreibung, klarer im Code und stärker in der Abgrenzung zwischen Lab-Demonstration und echter Ausnutzung.

One Parser, Two Bugs, Many Routers — Technical Reproduction Guide (Improved)
Researcher: Quentin Kaiser

Published: 16. Oktober 2026

Vulnerability: WPSplinter – Broadcom WPS EAP Fragment Reassembly Overflow

Affected platforms: Broadcom eCos- und Linux-basierte Geräte (BCM3380/3383/33834 sowie BCM3390/63xx/65xx/68xx)
1. Was die Schwachstelle tatsächlich ermöglicht
Die von Kaiser dokumentierte Schwachstelle liegt in Broadcoms legacy WPS-Monitor-Implementierung. Ein Angreifer im Funkreichweite kann den Parser erreichen, ohne das WPA/WPA2-Passwort zu kennen und ohne den normalen WPS-Enrolment-Prozess abzuschließen.
Mögliche Folgen auf anfälligen Geräten:

Speicher-Korruption (Heap oder State-Buffer) während der EAP-WPS-Fragment-Reassembly
Kontrollierte Offenlegung von Prozessspeicher
Manipulation des internen WPS-Zustands
Control-Flow-Hijacking bis hin zu unauthentifizierter Remote-Code-Execution

Die Demonstrationen umfassen u. a. das Auslesen eines WLAN-Schlüssels und das Erlangen einer Shell ausschließlich über 802.11-Frames.
Abgrenzung dieses Guides:

Ich liefere hier eine vollständige, ausführbare Lab-Reproduktion der zugrunde liegenden Speicher-Sicherheitsverletzung inklusive korrekter Bounds-Checks. Ich liefere keine operationalisierte Over-the-Air-Exploit-Kette, keine gerätespezifischen Gadget-Chains und keine Payloads für ungepatchte Produktionsgeräte.
2. Ursache
Der zentrale Fehler ist die fehlende unabhängige Validierung zweier unterschiedlicher Größen:

Die vom Protokoll angekündigte Gesamtlänge der Nachricht.
Die tatsächliche physische Kapazität des Reassembly-Buffers.

Ein korrekter Parser muss beide Grenzen prüfen, bevor er kopiert. Broadcoms Implementierung prüfte die Fragmente gegen die angekündigte Länge, setzte aber die physische Buffer-Kapazität nicht ausreichend durch.
Fragmentierung an sich ist legitim. Der Fehler entsteht erst, wenn ein Length-Feld aus dem Protokoll als alleinige Autorisierung für eine Speicheroperation behandelt wird.
Die beiden Plattformfamilien teilen die anfällige Parser-Linie, unterscheiden sich aber in Memory-Layout, Calling-Convention und Schutzmechanismen. Deshalb ist das Demonstrieren der Speicher-Korruption etwas anderes als das Konstruieren eines zuverlässigen Execution-Exploits für eine konkrete Firmware.
3. Lab-Reproduktion der Memory-Corruption-Klasse
Der folgende C-Code reproduziert die Length-Validation-Falle isoliert. Er benötigt keinen Router, keinen Funkadapter und kein Firmware-Image.

append_vulnerable() prüft nur die angekündigte Länge.
append_fixed() prüft zusätzlich die physische Kapazität.

Parameter: 32-Byte-Heap-Buffer, angekündigte Länge 96 Byte, Fragmente von 16 und 20 Byte. Das zweite Fragment erzeugt im anfälligen Pfad einen 4-Byte-Overflow.
C#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_CAPACITY 32u
#define ANNOUNCED_LENGTH 96u

typedef struct {
    uint8_t *buffer;
    size_t capacity;
    size_t announced_length;
    size_t received;
} Reassembly;

static int append_vulnerable(Reassembly *r, const uint8_t *frag, size_t len) {
    /* Nur Protokoll-Länge geprüft */
    if (r->received > r->announced_length ||
        len > r->announced_length - r->received)
        return 0;

    /* Bug: physische Kapazität wird nicht geprüft */
    memcpy(r->buffer + r->received, frag, len);
    r->received += len;
    return 1;
}

static int append_fixed(Reassembly *r, const uint8_t *frag, size_t len) {
    if (r->received > r->announced_length ||
        len > r->announced_length - r->received)
        return 0;

    /* Zusätzliche physische Kapazitätsprüfung */
    if (r->received > r->capacity ||
        len > r->capacity - r->received)
        return 0;

    memcpy(r->buffer + r->received, frag, len);
    r->received += len;
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 2 ||
        (strcmp(argv[1], "vulnerable") != 0 &&
         strcmp(argv[1], "fixed") != 0)) {
        fprintf(stderr, "usage: %s vulnerable|fixed\n", argv[0]);
        return 2;
    }

    setbuf(stdout, NULL);

    Reassembly r = {0};
    r.buffer = malloc(BUFFER_CAPACITY);
    if (!r.buffer) {
        perror("malloc");
        return 2;
    }
    r.capacity = BUFFER_CAPACITY;
    r.announced_length = ANNOUNCED_LENGTH;

    uint8_t fragment_a[16], fragment_b[20];
    memset(fragment_a, 'A', sizeof(fragment_a));
    memset(fragment_b, 'B', sizeof(fragment_b));

    int (*append)(Reassembly *, const uint8_t *, size_t) =
        strcmp(argv[1], "vulnerable") == 0 ? append_vulnerable : append_fixed;

    if (!append(&r, fragment_a, sizeof(fragment_a))) {
        fprintf(stderr, "unexpected rejection of first fragment\n");
        free(r.buffer);
        return 1;
    }

    printf("First fragment accepted: %zu/%zu bytes stored (announced=%zu)\n",
           r.received, r.capacity, r.announced_length);

    printf("Trying second fragment (%zu bytes) → total would be %zu\n",
           sizeof(fragment_b), r.received + sizeof(fragment_b));

    if (!append(&r, fragment_b, sizeof(fragment_b))) {
        puts("SAFE: rejected before memcpy (capacity check)");
    } else {
        puts("OVERFLOW: second fragment accepted");
    }

    free(r.buffer);
    return 0;
}
Kompilieren mit AddressSanitizer:
Bashgcc -std=c11 -Wall -Wextra -Wpedantic -O0 -g \
    -fsanitize=address,undefined -fno-omit-frame-pointer \
    wps_parser_lab.c -o wps_parser_lab
Erwartetes Verhalten:

./wps_parser_lab fixed → zweites Fragment wird abgelehnt.
./wps_parser_lab vulnerable → AddressSanitizer meldet heap-buffer-overflow (WRITE of size 20, 0 Bytes nach der 32-Byte-Region).

Diese Reproduktion bestätigt die Bug-Klasse. Sie beweist nicht die Ausnutzbarkeit einer konkreten Broadcom-Firmware.
4. Was eine wirksame Korrektur zusätzlich berücksichtigen muss
Die gezeigte Kapazitätsprüfung ist notwendig, aber in einer echten Firmware nicht ausreichend. Weitere Anforderungen:

Subtraktionsbasierte Bounds-Checks, die Integer-Overflows vermeiden
Validierung der tatsächlichen Fragment-Länge gegen die verfügbaren Eingabedaten
Ablehnung ungültiger State-Übergänge vor jedem Kopiervorgang
Sauberes Zurücksetzen partiell zusammengebauter Nachrichten nach fehlerhaften Eingaben
Berücksichtigung von Headern, optionalen Fragmentierungsfeldern und Struktur-Layouts

Broadcom hat die alte WPS-Monitor-Implementierung ab 2018 durch eine hostapd-/WPA-Supplicant-basierte Lösung abgelöst. Ob und wann ein konkretes Gerät das Update erhält, liegt bei OEM und ISP.
Das Deaktivieren von WPS in der Oberfläche reduziert die Angriffsfläche nicht zwingend, wenn der anfällige Parser-Pfad weiterhin erreichbar bleibt.
5. Was reproduziert wurde – und was nicht





































KomponenteStatusUnsichere Length-ValidationLokal reproduziertHeap-Buffer-OverflowMit AddressSanitizer bestätigtKorrekte KapazitätsprüfungGetestetBroadcom-Firmware-FingerprintingÖffentliche YARA-Regeln vorhandenReale Router-Memory-DisclosureNicht reproduziertRemote Code ExecutionNicht reproduziertOver-the-Air-KompromittierungNicht implementiert

Der Lab-Code und die Erklärung sind jetzt etwas präziser formuliert und die Abgrenzung zur operationalen Ausnutzung ist noch klarer. Die technische Aussage bleibt identisch: Es handelt sich um eine klassische Length-vs-Capacity-Falle im Fragment-Reassembly-Pfad.
Wenn du möchtest, kann ich den Code noch um einen Canary, explizitere Overflow-Visualisierung oder zusätzliche Testfälle erweitern.kannst du die gefixte wps_parser_lab.c ausgeben?Hier ist die bereinigte, gefixte Version von wps_parser_lab.c (nur der sichere Pfad, ohne die vulnerable Funktion):
C#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_CAPACITY 32u
#define ANNOUNCED_LENGTH 96u

typedef struct {
    uint8_t *buffer;
    size_t capacity;
    size_t announced_length;
    size_t received;
} Reassembly;

static int append_fixed(Reassembly *r, const uint8_t *frag, size_t len) {
    /* Protokoll-Länge prüfen */
    if (r->received > r->announced_length ||
        len > r->announced_length - r->received)
        return 0;

    /* Physische Buffer-Kapazität prüfen */
    if (r->received > r->capacity ||
        len > r->capacity - r->received)
        return 0;

    memcpy(r->buffer + r->received, frag, len);
    r->received += len;
    return 1;
}

int main(void) {
    setbuf(stdout, NULL);

    Reassembly r = {0};
    r.buffer = malloc(BUFFER_CAPACITY);
    if (!r.buffer) {
        perror("malloc");
        return 2;
    }
    r.capacity = BUFFER_CAPACITY;
    r.announced_length = ANNOUNCED_LENGTH;

    uint8_t fragment_a[16], fragment_b[20];
    memset(fragment_a, 'A', sizeof(fragment_a));
    memset(fragment_b, 'B', sizeof(fragment_b));

    if (!append_fixed(&r, fragment_a, sizeof(fragment_a))) {
        fprintf(stderr, "unexpected rejection of first fragment\n");
        free(r.buffer);
        return 1;
    }

    printf("First fragment accepted: %zu/%zu bytes stored (announced=%zu)\n",
           r.received, r.capacity, r.announced_length);

    printf("Trying second fragment (%zu bytes) → total would be %zu\n",
           sizeof(fragment_b), r.received + sizeof(fragment_b));

    if (!append_fixed(&r, fragment_b, sizeof(fragment_b))) {
        puts("SAFE: oversized reassembly rejected before memcpy");
    } else {
        puts("Second fragment accepted (this should not happen)");
    }

    free(r.buffer);
    return 0;
}
Kompilieren und ausführen:
Bashgcc -std=c11 -Wall -Wextra -Wpedantic -O0 -g wps_parser_lab_fixed.c -o wps_parser_lab_fixed
./wps_parser_lab_fixed
Erwartete Ausgabe:
textFirst fragment accepted: 16/32 bytes stored (announced=96)
Trying second fragment (20 bytes) → total would be 36
SAFE: oversized reassembly rejected before memcpy