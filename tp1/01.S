/**
 * @file   01h.S
 * @author Raphaël Monrouzeau <monrou_r@epitech.net>
 * @date   Sun Apr  4 23:46:35 2004
 *
 * @brief Le classique "hello world" mais en asm avec une traduction
 * en pseudo C.
 *
 * La transcription que je donne en commentaire est une
 * indication, elle contient une "erreur".
 * 
 * En fait l'equivalent C de ce programme ne declarerait aucune
 * variable, le depot sur la pile de 12, message puis 1 fait
 * partie de l'appel a write: c'est le passage d'arguments.
 * 
 * Il faudrait donc remplacer
 * 
 * size_t count = 12;
 * const void*buf = message;
 * int fd = 1;
 * write(fd, buf, count);
 * 
 * par un simple
 * 
 * write(1, message, 12);
 * 
 * mais je trouvais cela moins parlant pour un premier exemple.
 * 
 * 
 * 
 * Ce premier exemple est en francais (mais sans les accents
 * comme vous l'avez sans doute remarque). Ce ne sera sans doute
 * pas le cas des suivants. Tout le vocabulaire associe a cette
 * matiere est anglais et a mal ete traduit en francais (souvent
 * mot a mot) et la majorite de la documentation n'est disponible
 * qu'en anglais.
 * 
 * Si cela vous gene reellement envoyez-moi un courriel (en
 * groupe si possible).
 * 
 * Et n'oubliez pas de lire le fichier en-tete.
 *
 */

#include		"01.h"


STATIC_CONST(message)		// static const char message[] =
	.asciz "hello world\12"	// "hello world\n";
OBJECT_END(message)


GLOBAL_FUNC(main)		// main()
	pushl	%ebp		//
	movl	%esp, %ebp	// {
	pushl	$12		//   size_t count = 12;
	pushl	$message	//   const void*buf = message;
	pushl	$1		//   int fd = 1;
	call	write		//   write(fd, buf, count);
	movl	$0, %eax	//   return 0;
	leave			// }
	ret			//
FUNC_END(main)

