# ThinkLink

Projekt realizowany w ramach Kościuszkonu 2026 nagrodzony II miejscem w kategorii Cybersecurity Awareness.

ThinkLink to zaawansowana wtyczka do przeglądarki, która zwiększa poziom bezpieczeństwa podczas korzystania z Internetu. Zamiast polegać na statycznych czarnych listach, narzędzie wykorzystuje sztuczną inteligencję i analizę danych w czasie rzeczywistym, aby chronić użytkowników przed phishingiem, złośliwym oprogramowaniem i podejrzanymi przekierowaniami. 
Obsługiwane przez wtyczkę funkcjonalności to:
- Analiza DOM w czasie rzeczywistym
- Analiza zagrożonej strony - wtyczka sprawdza wszystkie linki, przekierowania czy reklamy znajdujące się na stronie przy pomocy heurystyk, a następnie w przypadku wystąpienia zagrożenia następuje analiza przy pomocy AI (Groq)
- Tryb prosty lub tryb ekspert - w trybie prostym zwykły użytkownik dostaje informacje o tym czy np. link jest niebezpieczny i w jakim stopniu, w trybie eksperta użytkownik z szerszą wiedzą może poznać szczegóły dotyczące występujących zagrożeń
- Raport z wykrytego zagrożenia w linku - szczegółowe informacje o niebezpiecznej stronie w tym m.in. jej wskaźniki zagrożenia, informacje o domenie, łańcuch możliwych przekierowań oraz opis przebiegu czynności wykonanych przez AI (Groq) na niebezpiecznej domenie
- Blokada niebezpiecznych linków - w przypadku wystąpienia niebezpiecznych przekierowań następuje zablokowanie możliwości kliknięcia w domenę przez użytkownika w celach bezpieczeństwa
- Podsumowanie zagrożeń na stronie - użytkownik ma informacje o liczbie zablokowanych linków w ramach strony
- Dodawanie bezpiecznych stron (white lista) - użytkownik ma możliwość dodania zaufanych domen do whitelisty
- Wielowarstwowa weryfikacja URL - wtyczka sprawdza czy podczas przekierowania do podanej na stronie domeny następuje pobranie podejrzanych plików, czy od razu nie przekierowuje dalej do potencjalnej niebezpiecznej strony HTTP oraz kiedy domena została utworzona
- Bot weryfikujący wystąpienie phishingu - użytkownik ma możliwość wklejenia podejrzanej wiadomości, która jest weryfikowana przez heurystyki lub przez model AI (Groq), a następnie dostaje analizę podanej wiadomości
