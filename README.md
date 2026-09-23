# Notible Sync

> **Dwa pluginy sync, dwa przeznaczenia.** Ten (`notible.sync`) to wersja
> **z parowaniem**: klucz nie opuszcza Twoich urządzeń, dodanie kolejnej
> maszyny wymaga świadomego kroku. Wersja **bez parowania** (wygoda kosztem
> prywatności) to `plugins/notible-sync-simple`. Osobne foldery na Dysku,
> osobne id — nie mieszają się.

Replikacja workspace'u między Twoimi własnymi maszynami przez Twój własny
Dysk Google. Nie ma serwera Notible i nie może go być: wszystko, co opuszcza
urządzenie, jest zaszyfrowane kluczem, który mają wyłącznie Twoje urządzenia.

Wymaga Notible **0.59.0** lub nowszego (Plugin API 1.7 — uprawnienia `network`
i `data.sync`, w tym `data.sync.media` dla obrazów oraz logowanie przez
przeglądarkę bez przepisywania kodu).

> **Uwaga na „Remove" w Plugin host.** Do 0.48.1 włącznie usunięcie pluginu
> zainstalowanego z folderu **kasuje ten folder z dysku** (`db.rs:3414`
> woła `remove_dir_all` na `install_path`, którym dla instalacji lokalnej jest
> Twój katalog źródłowy). Trzymaj źródła w gicie albo poza katalogiem, który
> wskazujesz aplikacji, dopóki nie wyjdzie 0.48.2.

## Jak to działa

Każde urządzenie zapisuje **jeden plik** — `device-<id>.json` — w widocznym
folderze `Notible Sync` na Dysku, i czyta pliki pozostałych urządzeń. Nikt nie
pisze do cudzego pliku, więc nie ma konfliktów zapisu, blokad ani CRDT.

Plugin czyta i zapisuje przez `context.data.sync`, czyli dziennik zmian, który
Notible prowadzi przy każdym zapisie. Dzięki temu kasowanie propaguje się przez
prawdziwe tombstones, a nie przez zgadywanie „obiektu nie ma, czyli zniknął".

## Pierwsze uruchomienie

1. Na pierwszym urządzeniu: Ustawienia → Plugin panels → Notible Sync →
   **Sign in with Google**, potem **Create a new key**.
2. Przepisz klucz na drugie urządzenie i wpisz go tam w to samo pole.
3. **Synchronise now** po obu stronach.

Kolejność pierwszego kliknięcia nie ma znaczenia. Nic się nie scala i nic nie
znika: jeśli masz projekt „Scania" na obu maszynach, zostaną **dwa** projekty,
bo to dwa różne obiekty. Sklejenie ich to osobna, ręczna decyzja.

## Obrazy

Wklejone zrzuty ekranu jadą **osobnym plikiem na Dysk, raz na obrazek** —
nazwa jest UUID-em, więc plik, który już tam jest, jest tym właściwym. Nie w
migawce: migawka leci co cykl, a 20 MB zrzutu w środku to nie synchronizacja,
tylko rachunek za transfer. Leżą w podfolderze `media/`, osobno od migawek.

**Musisz to najpierw włączyć:** Ustawienia → Plugin host → „Let plugins read
pasted images". Domyślnie wyłączone i włączenie otwiera natywne okno. Powód
jest nieprzyjemny i lepiej, żebyś go znał: Notible nie umie odróżnić wtyczek
od siebie, więc gdy to włączysz, **każda** zainstalowana wtyczka może czytać
Twoje wklejone obrazy i wysłać je gdziekolwiek. Trzymaj to włączone tylko
wtedy, gdy synchronizujesz, i tylko z wtyczkami, którym ufasz.

Bez włączenia reszta działa normalnie — notatki jeżdżą, a status mówi raz
„images not sent".

Czego nie ma: obrazek skasowany na jednej maszynie **nie znika** z Dysku ani
z drugiej maszyny. Nagrobek pliku to kolejna droga do nieodwracalnej utraty
danych, a osierocony obraz kosztuje miejsce.

## Czego ten plugin nie robi

- **Nie synchronizuje załączników innych niż obrazy.** Wklejone obrazy
  jeżdżą od 0.2.0 (wymaga Notible 0.56.0), reszta plików nie.
- **Nie scala duplikatów.** Osobna funkcja, jeszcze nie napisana.
- **Nie jest czasem rzeczywistym.** Domyślnie automatycznie: przy starcie, ok. minutę po zmianie i co N minut (można wyłączyć). Panel pokazuje, kiedy każde urządzenie ostatnio wysłało zmiany.
- **Edycja na dwóch urządzeniach naraz.** Tabele scalają się po komórkach (kolumna dodana tu i komórka zmieniona tam przetrwają obie). Wszystko inne, albo ta sama komórka zmieniona po obu stronach: zostaje nowsza wersja, a przegrana ląduje obok jako „(conflict copy — urządzenie, data)”. Kopię robi tylko urządzenie, którego wersja przegrała. Wykrywanie działa od drugiego sync na tej wersji pluginu (wcześniej nie ma punktu odniesienia).

## Rzeczy, które musisz wiedzieć, zanim to włączysz

**Utrata klucza to utrata dostępu do kopii na Dysku.** Klucz nie jest nigdzie
wysyłany, więc nie da się go odzyskać. Twoje lokalne notatki są przy tym
całkowicie bezpieczne — tracisz kopię, nie dane.

**Każde sparowane urządzenie jest równie zaufane.** Szyfrowanie dowodzi, że
migawkę zapisał ktoś posiadający klucz; nie odróżnia laptopa od PC. To właściwy
model dla własnych maszyn, ale nie wystarczyłby do dzielenia workspace'u
z inną osobą.

**Sekretu OAuth nie ma już w tym pliku.** Od API 1.7 klient i scope'y należą
do Core (`plugin_oauth.rs`), a plugin podaje tylko nazwę providera
(`google.drive.file`). Powód nie jest kosmetyczny: komenda, której wywołujący
mógłby podać własny `client_id` i scope'y, pozwoliłaby **dowolnej**
zainstalowanej wtyczce wyświetlić prawdziwy ekran zgody Google z prośbą
o cokolwiek. Sufit jest teraz sztywny i wynosi `drive.file`.

**Logowanie nie ma już kodu do przepisywania.** Device flow (`google.com/device`
plus kod) był tam, bo plugin nie ma gniazda, na którym złapałby
przekierowanie. Core ma, więc używa flow przeznaczonego dla aplikacji
desktopowych: otwiera przeglądarkę, łapie odpowiedź na `127.0.0.1`, koniec.

**Token odświeżający leży w `context.storage`**, czyli w `localStorage`
webview. Każdy inny zainstalowany plugin może go odczytać. Dlatego „Sign out"
robi też `revoke` po stronie Google — wylogowuj się, jeśli przestajesz
używać.

**Folder `Notible Sync` jest widoczny na Twoim Dysku** i możesz go skasować.
To nie skasuje niczego w notatkach: brak pliku peera nigdy nie jest odczytywany
jako polecenie usunięcia.

## Sprawdzian

```
node plugins/notible-sync/self-check.mjs
```

Pokrywa tożsamość manifestu, kodowanie klucza, round-trip zaszyfrowanej
migawki, odrzucenie migawki podpisanej innym kluczem i migawki ze zmienionym
bitem, walidację cudzych danych oraz odkładanie zmian do otwartej notatki.

## Install

In Notible: **Settings -> Plugins -> Market**, then install "Notible Sync".
This repo is the source; the market pulls `plugin.json` + `notible.sync.zip` from the latest GitHub Release.
