/**
 * @file   symbol_macros.h
 * @author Raphaël Monrouzeau <monrou_r@epitech.net>
 * @date   Sun Apr  4 23:22:22 2004
 * 
 * @brief  Macros de definition et declaration de symboles.
 * 
 *	Toutes les explications fournies ici ne sont qu'un bref
 *	resume, n'hesitez pas a consulter la documentation de
 *	reference des outils pour chacune de leurs fonctionalites que
 *	vous ne connaissez pas.
 *
 *	info as
 *	info ld
 *	info make (parle de gmake)
 *	info gcc
 *
 */

#if			!defined(__symbol_macros_h__)
#  define		__symbol_macros_h__

/**
 * Niveau d'alignement des fonctions en octet.
 *
 * L'IA32 ne requiert pas que les pointeurs aient des valeurs
 * multiples d'une certaine puissance de deux (cela est courant sur
 * les autres architectures), mais c'est fortement recommande.
 *
 * Les acces directs a la memoire via une addresse non multiple de 4
 * (on dit que la donnee a laquelle on veut acceder est non alignee)
 * seront beaucoup plus lents.
 *
 * Pour plusieurs raisons il est meme conseille d'aligner sur 8 voir
 * 16.
 */
#  define		FUNC_ALIGN	16

/**
 * Niveau d'alignement des donnees en octets.
 */
#  define		DATA_ALIGN	16


/* -------------------------------------------------------------------- */


/**
 * Declare un symbole comme faisant reference a une fonction globale,
 * puis debute sa definition.
 *
 * Avant tout ceci, la macro se place temporairement dans la section
 * .text.
 */
#define	GLOBAL_FUNC(name)						\
.pushsection .text;							\
	.global	name;							\
	.type	name,"function";					\
	.func	name;							\
	.balign	FUNC_ALIGN, FUNC_ALIGN;					\
	name:

/**
 * Declare un symbole comme faisant reference a une fonction statique,
 * puis debute sa definition.
 */
#define	STATIC_FUNC(name)						\
.pushsection .text;							\
	.local	name;							\
	.type	name,"function";					\
	.func	name;							\
	.balign	FUNC_ALIGN, FUNC_ALIGN;					\
	name:

/**
 * Met fin a la definition d'une fonction et renseigne sa taille dans
 * la table des symboles.
 *
 * Ensuite retourne dans la section ou l'assembleur se trouvait avant
 * la definition.
 */
#define FUNC_END(name)							\
	.endfunc;							\
	.size name, . - name;						\
.popsection


/* -------------------------------------------------------------------- */


/**
 * Declare un symbole comme faisant reference a des donnees globales
 * et constantes, puis debute leur definition.
 */
#define GLOBAL_CONST(name)						\
.pushsection	.rodata;						\
	.global	name;							\
	.type	name,"object";						\
	.balign	DATA_ALIGN, DATA_ALIGN;					\
	name:

/**
 * Declare un symbole comme faisant reference a des donnees statiques
 * et constantes, puis debute leur definition.
 */
#define STATIC_CONST(name)						\
.pushsection	.rodata;						\
	.local	name;							\
	.type	name,"object";						\
	.balign	DATA_ALIGN, DATA_ALIGN;					\
	name:

/**
 * Declare un symbole comme faisant reference a des donnees globales,
 * puis debute leur definition.
 */
#define GLOBAL(name)							\
.pushsection	.data;							\
	.global	name;							\
	.type	name,"object";						\
	.balign	DATA_ALIGN, DATA_ALIGN;					\
	name:

/**
 * Declare un symbole comme faisant reference a des donnees statiques,
 * puis debute leur definition.
 */
#define STATIC(name)							\
.pushsection	.data;							\
	.local	name;							\
	.type	name,"object";						\
	.balign	DATA_ALIGN, DATA_ALIGN;					\
	name:

/**
 * Declare un symbole comme faisant reference a des donnees globales
 * qui seront initialisees a 0, puis debute leur definition.
 */
#define GLOBAL0(name)							\
.pushsection	.bss;							\
	.global	name;							\
	.type	name,"object";						\
	.balign	DATA_ALIGN, DATA_ALIGN;					\
	name:

/**
 * Declare un symbole comme faisant reference a des donnees statiques
 * qui seront initialisees a 0, puis debute leur definition.
 */
#define STATIC0(name)							\
.pushsection	.bss;							\
	.local	name;							\
	.type	name,"object";						\
	.balign	DATA_ALIGN, DATA_ALIGN;					\
	name:

/**
 * Met fin a la definition de donnees et renseigne leur taille dans la
 * table des symboles.
 */
#define OBJECT_END(name)						\
	.size	name, . - name;						\
.popsection


#endif			/* __symbol_macros_h__ */
