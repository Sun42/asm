1-Retouver l'imageBase de kernel32.dll qui se trouve dans tib->peb->InInializationOrderList(3)
2-Parser l'export Table de kernel32.dll et recuperer les fonctions LoadLibrary et GetProcAddress:
                 2.1 trouver l'indice de la fonction dans la Table AdressOFNames
		 2.2-Recuperer l'adresse de la fonction dans l'ordinalTable(indice)
