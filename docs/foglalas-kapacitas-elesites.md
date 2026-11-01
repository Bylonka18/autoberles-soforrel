# Foglalási rendszer élesítési ellenőrzőlista

Fejlesztői ág. Nem éles.

## Jelenlegi állapot
A web-api foglalasIdopontJavaslatok és foglalasKuldes már a közös bookingCapacity függvényt használja. A funkció figyeli az előző és következő napot, a kiosztott sofőröket és a minél hamarabbi fuvarokat. Az előzetes kapacitásellenőrzés és a fuvarok INSERT között versenyhelyzet lehetséges.

A foglalas-v2-teszt 7-es verziója központi OSRM útvonalakat használ, nem pontos házszámokat. GPS-alapú sorvizsgálat hiányában ASAP rendelés esetén hibát ad. Nem alkalmas közvetlen éles cserére.

## Fejlesztési feladatok
1. Az éles bookingCapacity pontos koordinátás útvonalszámításának ellenőrzése.
2. A kapacitásvizsgálat és a végleges mentés egyetlen atomikus adatbázis-tranzakcióban történjen. Egyidejű foglalások ne foglaljanak ugyanarra a sofőrre ütköző fuvart.
3. Az e-mail megerősítésre váró foglalás és a lejáró token helyes kapacitáskezelése.
4. Az admin és sofőr által létrehozott időpontos fuvarok azonos ellenőrzést kapjanak.

## Kötelező tesztek
- Egy sofőr, két egyidejű ütköző rendelés: legfeljebb egy sikeres.
- Két sofőr: a ténylegesen teljesíthető fuvarok elfogadása.
- Előző napi és következő napi, éjfél körüli átfedés.
- Nyári és téli óraátállítás.
- ASAP rendelés GPS-szel és GPS nélkül.
- Kész, lemondott és törölt fuvar ne foglaljon kapacitást.
- Web és mobilapp azonos eredményt adjon.
- E-mailes megerősítés, lejárat, dupla kattintás.
- Tesztelés valós ügyfélértesítés és valódi fuvar létrehozása nélkül.

Élesítés csak a fenti tesztek sikeres teljesítése után.