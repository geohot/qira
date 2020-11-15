/*
 * Copyright (C) 2012 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/efi_strings.h>
#include <ipxe/efi/efi_hii.h>

/** Tiano GUID */
static const EFI_GUID tiano_guid = EFI_IFR_TIANO_GUID;

/**
 * Add string to IFR builder
 *
 * @v ifr		IFR builder
 * @v fmt		Format string
 * @v ...		Arguments
 * @ret string_id	String identifier, or zero on failure
 */
unsigned int efi_ifr_string ( struct efi_ifr_builder *ifr, const char *fmt,
			      ... ) {
	EFI_HII_STRING_BLOCK *new_strings;
	EFI_HII_SIBT_STRING_UCS2_BLOCK *ucs2;
	size_t new_strings_len;
	va_list args;
	size_t len;
	unsigned int string_id;

	/* Do nothing if a previous allocation has failed */
	if ( ifr->failed )
		return 0;

	/* Calculate string length */
	va_start ( args, fmt );
	len = ( efi_vsnprintf ( NULL, 0, fmt, args ) + 1 /* wNUL */ );
	va_end ( args );

	/* Reallocate strings */
	new_strings_len = ( ifr->strings_len +
			    offsetof ( typeof ( *ucs2 ), StringText ) +
			    ( len * sizeof ( ucs2->StringText[0] ) ) );
	new_strings = realloc ( ifr->strings, new_strings_len );
	if ( ! new_strings ) {
		ifr->failed = 1;
		return 0;
	}
	ucs2 = ( ( ( void * ) new_strings ) + ifr->strings_len );
	ifr->strings = new_strings;
	ifr->strings_len = new_strings_len;

	/* Fill in string */
	ucs2->Header.BlockType = EFI_HII_SIBT_STRING_UCS2;
	va_start ( args, fmt );
	efi_vsnprintf ( ucs2->StringText, len, fmt, args );
	va_end ( args );

	/* Allocate string ID */
	string_id = ++(ifr->string_id);

	DBGC ( ifr, "IFR %p string %#04x is \"%ls\"\n",
	       ifr, string_id, ucs2->StringText );
	return string_id;
}

/**
 * Add IFR opcode to IFR builder
 *
 * @v ifr		IFR builder
 * @v opcode		Opcode
 * @v len		Opcode length
 * @ret op		Opcode, or NULL
 */
static void * efi_ifr_op ( struct efi_ifr_builder *ifr, unsigned int opcode,
			   size_t len ) {
	EFI_IFR_OP_HEADER *new_ops;
	EFI_IFR_OP_HEADER *op;
	size_t new_ops_len;

	/* Do nothing if a previous allocation has failed */
	if ( ifr->failed )
		return NULL;

	/* Reallocate opcodes */
	new_ops_len = ( ifr->ops_len + len );
	new_ops = realloc ( ifr->ops, new_ops_len );
	if ( ! new_ops ) {
		ifr->failed = 1;
		return NULL;
	}
	op = ( ( ( void * ) new_ops ) + ifr->ops_len );
	ifr->ops = new_ops;
	ifr->ops_len = new_ops_len;

	/* Fill in opcode header */
	op->OpCode = opcode;
	op->Length = len;

	return op;
}

/**
 * Add end opcode to IFR builder
 *
 * @v ifr		IFR builder
 */
void efi_ifr_end_op ( struct efi_ifr_builder *ifr ) {
	size_t dispaddr = ifr->ops_len;
	EFI_IFR_END *end;

	/* Add opcode */
	end = efi_ifr_op ( ifr, EFI_IFR_END_OP, sizeof ( *end ) );

	DBGC ( ifr, "IFR %p end\n", ifr );
	DBGC2_HDA ( ifr, dispaddr, end, sizeof ( *end ) );
}

/**
 * Add false opcode to IFR builder
 *
 * @v ifr		IFR builder
 */
void efi_ifr_false_op ( struct efi_ifr_builder *ifr ) {
	size_t dispaddr = ifr->ops_len;
	EFI_IFR_FALSE *false;

	/* Add opcode */
	false = efi_ifr_op ( ifr, EFI_IFR_FALSE_OP, sizeof ( *false ) );

	DBGC ( ifr, "IFR %p false\n", ifr );
	DBGC2_HDA ( ifr, dispaddr, false, sizeof ( *false ) );
}

/**
 * Add form opcode to IFR builder
 *
 * @v ifr		IFR builder
 * @v title_id		Title string identifier
 * @ret form_id		Form identifier
 */
unsigned int efi_ifr_form_op ( struct efi_ifr_builder *ifr,
			       unsigned int title_id ) {
	size_t dispaddr = ifr->ops_len;
	EFI_IFR_FORM *form;

	/* Add opcode */
	form = efi_ifr_op ( ifr, EFI_IFR_FORM_OP, sizeof ( *form ) );
	if ( ! form )
		return 0;
	form->Header.Scope = 1;
	form->FormId = ++(ifr->form_id);
	form->FormTitle = title_id;

	DBGC ( ifr, "IFR %p name/value store %#04x title %#04x\n",
	       ifr, form->FormId, title_id );
	DBGC2_HDA ( ifr, dispaddr, form, sizeof ( *form ) );
	return form->FormId;
}

/**
 * Add formset opcode to IFR builder
 *
 * @v ifr		IFR builder
 * @v guid		GUID
 * @v title_id		Title string identifier
 * @v help_id		Help string identifier
 * @v ...		Class GUIDs (terminated by NULL)
 */
void efi_ifr_form_set_op ( struct efi_ifr_builder *ifr, const EFI_GUID *guid,
			   unsigned int title_id, unsigned int help_id, ... ) {
	size_t dispaddr = ifr->ops_len;
	EFI_IFR_FORM_SET *formset;
	EFI_GUID *class_guid;
	unsigned int num_class_guids = 0;
	size_t len;
	va_list args;

	/* Count number of class GUIDs */
	va_start ( args, help_id );
	while ( va_arg ( args, const EFI_GUID * ) != NULL )
		num_class_guids++;
	va_end ( args );

	/* Add opcode */
	len = ( sizeof ( *formset ) +
		( num_class_guids * sizeof ( *class_guid ) ) );
	formset = efi_ifr_op ( ifr, EFI_IFR_FORM_SET_OP, len );
	if ( ! formset )
		return;
	formset->Header.Scope = 1;
	memcpy ( &formset->Guid, guid, sizeof ( formset->Guid ) );
	formset->FormSetTitle = title_id;
	formset->Help = help_id;
	formset->Flags = num_class_guids;

	/* Add class GUIDs */
	class_guid = ( ( ( void * ) formset ) + sizeof ( *formset ) );
	va_start ( args, help_id );
	while ( num_class_guids-- ) {
		memcpy ( class_guid++, va_arg ( args, const EFI_GUID * ),
			 sizeof ( *class_guid ) );
	}
	va_end ( args );

	DBGC ( ifr, "IFR %p formset title %#04x help %#04x\n",
	       ifr, title_id, help_id );
	DBGC2_HDA ( ifr, dispaddr, formset, len );
}

/**
 * Add get opcode to IFR builder
 *
 * @v ifr		IFR builder
 * @v varstore_id	Variable store identifier
 * @v varstore_info	Variable string identifier or offset
 * @v varstore_type	Variable type
 */
void efi_ifr_get_op ( struct efi_ifr_builder *ifr, unsigned int varstore_id,
		      unsigned int varstore_info, unsigned int varstore_type ) {
	size_t dispaddr = ifr->ops_len;
	EFI_IFR_GET *get;

	/* Add opcode */
	get = efi_ifr_op ( ifr, EFI_IFR_GET_OP, sizeof ( *get ) );
	get->VarStoreId = varstore_id;
	get->VarStoreInfo.VarName = varstore_info;
	get->VarStoreType = varstore_type;

	DBGC ( ifr, "IFR %p get varstore %#04x:%#04x type %#02x\n",
	       ifr, varstore_id, varstore_info, varstore_type );
	DBGC2_HDA ( ifr, dispaddr, get, sizeof ( *get ) );
}

/**
 * Add GUID class opcode to IFR builder
 *
 * @v ifr		IFR builder
 * @v class		Class
 */
void efi_ifr_guid_class_op ( struct efi_ifr_builder *ifr, unsigned int class ) {
	size_t dispaddr = ifr->ops_len;
	EFI_IFR_GUID_CLASS *guid_class;

	/* Add opcode */
	guid_class = efi_ifr_op ( ifr, EFI_IFR_GUID_OP,
				  sizeof ( *guid_class ) );
	if ( ! guid_class )
		return;
	memcpy ( &guid_class->Guid, &tiano_guid, sizeof ( guid_class->Guid ) );
	guid_class->ExtendOpCode = EFI_IFR_EXTEND_OP_CLASS;
	guid_class->Class = class;

	DBGC ( ifr, "IFR %p GUID class %#02x\n", ifr, class );
	DBGC2_HDA ( ifr, dispaddr, guid_class, sizeof ( *guid_class ) );
}

/**
 * Add GUID subclass opcode to IFR builder
 *
 * @v ifr		IFR builder
 * @v subclass		Subclass
 */
void efi_ifr_guid_subclass_op ( struct efi_ifr_builder *ifr,
				unsigned int subclass ) {
	size_t dispaddr = ifr->ops_len;
	EFI_IFR_GUID_SUBCLASS *guid_subclass;

	/* Add opcode */
	guid_subclass = efi_ifr_op ( ifr, EFI_IFR_GUID_OP,
				     sizeof ( *guid_subclass ) );
	if ( ! guid_subclass )
		return;
	memcpy ( &guid_subclass->Guid, &tiano_guid,
		 sizeof ( guid_subclass->Guid ) );
	guid_subclass->ExtendOpCode = EFI_IFR_EXTEND_OP_SUBCLASS;
	guid_subclass->SubClass = subclass;

	DBGC ( ifr, "IFR %p GUID subclass %#02x\n", ifr, subclass );
	DBGC2_HDA ( ifr, dispaddr, guid_subclass, sizeof ( *guid_subclass ) );
}

/**
 * Add numeric opcode to IFR builder
 *
 * @v ifr		IFR builder
 * @v prompt_id		Prompt string identifier
 * @v help_id		Help string identifier
 * @v question_id	Question identifier
 * @v varstore_id	Variable store identifier
 * @v varstore_info	Variable string identifier or offset
 * @v vflags		Variable flags
 * @v min_value		Minimum value
 * @v max_value		Maximum value
 * @v step		Step
 * @v flags		Flags
 */
void efi_ifr_numeric_op ( struct efi_ifr_builder *ifr, unsigned int prompt_id,
			  unsigned int help_id, unsigned int question_id,
			  unsigned int varstore_id, unsigned int varstore_info,
			  unsigned int vflags, unsigned long min_value,
			  unsigned long max_value, unsigned int step,
			  unsigned int flags ) {
	size_t dispaddr = ifr->ops_len;
	EFI_IFR_NUMERIC *numeric;
	unsigned int size;

	/* Add opcode */
	numeric = efi_ifr_op ( ifr, EFI_IFR_NUMERIC_OP, sizeof ( *numeric ) );
	if ( ! numeric )
		return;
	numeric->Question.Header.Prompt = prompt_id;
	numeric->Question.Header.Help = help_id;
	numeric->Question.QuestionId = question_id;
	numeric->Question.VarStoreId = varstore_id;
	numeric->Question.VarStoreInfo.VarName = varstore_info;
	numeric->Question.Flags = vflags;
	size = ( flags & EFI_IFR_NUMERIC_SIZE );
	switch ( size ) {
	case EFI_IFR_NUMERIC_SIZE_1 :
		numeric->data.u8.MinValue = min_value;
		numeric->data.u8.MaxValue = max_value;
		numeric->data.u8.Step = step;
		break;
	case EFI_IFR_NUMERIC_SIZE_2 :
		numeric->data.u16.MinValue = min_value;
		numeric->data.u16.MaxValue = max_value;
		numeric->data.u16.Step = step;
		break;
	case EFI_IFR_NUMERIC_SIZE_4 :
		numeric->data.u32.MinValue = min_value;
		numeric->data.u32.MaxValue = max_value;
		numeric->data.u32.Step = step;
		break;
	case EFI_IFR_NUMERIC_SIZE_8 :
		numeric->data.u64.MinValue = min_value;
		numeric->data.u64.MaxValue = max_value;
		numeric->data.u64.Step = step;
		break;
	}

	DBGC ( ifr, "IFR %p numeric prompt %#04x help %#04x question %#04x "
	       "varstore %#04x:%#04x\n", ifr, prompt_id, help_id, question_id,
	       varstore_id, varstore_info );
	DBGC2_HDA ( ifr, dispaddr, numeric, sizeof ( *numeric ) );
}

/**
 * Add string opcode to IFR builder
 *
 * @v ifr		IFR builder
 * @v prompt_id		Prompt string identifier
 * @v help_id		Help string identifier
 * @v question_id	Question identifier
 * @v varstore_id	Variable store identifier
 * @v varstore_info	Variable string identifier or offset
 * @v vflags		Variable flags
 * @v min_size		Minimum size
 * @v max_size		Maximum size
 * @v flags		Flags
 */
void efi_ifr_string_op ( struct efi_ifr_builder *ifr, unsigned int prompt_id,
			 unsigned int help_id, unsigned int question_id,
			 unsigned int varstore_id, unsigned int varstore_info,
			 unsigned int vflags, unsigned int min_size,
			 unsigned int max_size, unsigned int flags ) {
	size_t dispaddr = ifr->ops_len;
	EFI_IFR_STRING *string;

	/* Add opcode */
	string = efi_ifr_op ( ifr, EFI_IFR_STRING_OP, sizeof ( *string ) );
	if ( ! string )
		return;
	string->Question.Header.Prompt = prompt_id;
	string->Question.Header.Help = help_id;
	string->Question.QuestionId = question_id;
	string->Question.VarStoreId = varstore_id;
	string->Question.VarStoreInfo.VarName = varstore_info;
	string->Question.Flags = vflags;
	string->MinSize = min_size;
	string->MaxSize = max_size;
	string->Flags = flags;

	DBGC ( ifr, "IFR %p string prompt %#04x help %#04x question %#04x "
	       "varstore %#04x:%#04x\n", ifr, prompt_id, help_id, question_id,
	       varstore_id, varstore_info );
	DBGC2_HDA ( ifr, dispaddr, string, sizeof ( *string ) );
}

/**
 * Add suppress-if opcode to IFR builder
 *
 * @v ifr		IFR builder
 */
void efi_ifr_suppress_if_op ( struct efi_ifr_builder *ifr ) {
	size_t dispaddr = ifr->ops_len;
	EFI_IFR_SUPPRESS_IF *suppress_if;

	/* Add opcode */
	suppress_if = efi_ifr_op ( ifr, EFI_IFR_SUPPRESS_IF_OP,
				   sizeof ( *suppress_if ) );
	suppress_if->Header.Scope = 1;

	DBGC ( ifr, "IFR %p suppress-if\n", ifr );
	DBGC2_HDA ( ifr, dispaddr, suppress_if, sizeof ( *suppress_if ) );
}

/**
 * Add text opcode to IFR builder
 *
 * @v ifr		IFR builder
 * @v prompt_id		Prompt string identifier
 * @v help_id		Help string identifier
 * @v text_id		Text string identifier
 */
void efi_ifr_text_op ( struct efi_ifr_builder *ifr, unsigned int prompt_id,
		       unsigned int help_id, unsigned int text_id ) {
	size_t dispaddr = ifr->ops_len;
	EFI_IFR_TEXT *text;

	/* Add opcode */
	text = efi_ifr_op ( ifr, EFI_IFR_TEXT_OP, sizeof ( *text ) );
	if ( ! text )
		return;
	text->Statement.Prompt = prompt_id;
	text->Statement.Help = help_id;
	text->TextTwo = text_id;

	DBGC ( ifr, "IFR %p text prompt %#04x help %#04x text %#04x\n",
	       ifr, prompt_id, help_id, text_id );
	DBGC2_HDA ( ifr, dispaddr, text, sizeof ( *text ) );
}

/**
 * Add true opcode to IFR builder
 *
 * @v ifr		IFR builder
 */
void efi_ifr_true_op ( struct efi_ifr_builder *ifr ) {
	size_t dispaddr = ifr->ops_len;
	EFI_IFR_TRUE *true;

	/* Add opcode */
	true = efi_ifr_op ( ifr, EFI_IFR_TRUE_OP, sizeof ( *true ) );

	DBGC ( ifr, "IFR %p true\n", ifr );
	DBGC2_HDA ( ifr, dispaddr, true, sizeof ( *true ) );
}

/**
 * Add name/value store opcode to IFR builder
 *
 * @v ifr		IFR builder
 * @v guid		GUID
 * @ret varstore_id	Variable store identifier, or 0 on failure
 */
unsigned int efi_ifr_varstore_name_value_op ( struct efi_ifr_builder *ifr,
					      const EFI_GUID *guid ) {
	size_t dispaddr = ifr->ops_len;
	EFI_IFR_VARSTORE_NAME_VALUE *varstore;

	/* Add opcode */
	varstore = efi_ifr_op ( ifr, EFI_IFR_VARSTORE_NAME_VALUE_OP,
				sizeof ( *varstore ) );
	if ( ! varstore )
		return 0;
	varstore->VarStoreId = ++(ifr->varstore_id);
	memcpy ( &varstore->Guid, guid, sizeof ( varstore->Guid ) );

	DBGC ( ifr, "IFR %p name/value store %#04x\n",
	       ifr, varstore->VarStoreId );
	DBGC2_HDA ( ifr, dispaddr, varstore, sizeof ( *varstore ) );
	return varstore->VarStoreId;
}

/**
 * Free memory used by IFR builder
 *
 * @v ifr		IFR builder
 */
void efi_ifr_free ( struct efi_ifr_builder *ifr ) {

	free ( ifr->ops );
	free ( ifr->strings );
	memset ( ifr, 0, sizeof ( *ifr ) );
}

/**
 * Construct package list from IFR builder
 *
 * @v ifr		IFR builder
 * @v guid		Package GUID
 * @v language		Language
 * @v language_id	Language string ID
 * @ret package		Package list, or NULL
 *
 * The package list is allocated using malloc(), and must eventually
 * be freed by the caller.  (The caller must also call efi_ifr_free()
 * to free the temporary storage used during construction.)
 */
EFI_HII_PACKAGE_LIST_HEADER * efi_ifr_package ( struct efi_ifr_builder *ifr,
						const EFI_GUID *guid,
						const char *language,
						unsigned int language_id ) {
	struct {
		EFI_HII_PACKAGE_LIST_HEADER header;
		struct {
			EFI_HII_PACKAGE_HEADER header;
			uint8_t data[ifr->ops_len];
		} __attribute__ (( packed )) ops;
		struct {
			union {
				EFI_HII_STRING_PACKAGE_HDR header;
				uint8_t pad[offsetof(EFI_HII_STRING_PACKAGE_HDR,
						     Language) +
					    strlen ( language ) + 1 /* NUL */ ];
			} __attribute__ (( packed )) header;
			uint8_t data[ifr->strings_len];
			EFI_HII_STRING_BLOCK end;
		} __attribute__ (( packed )) strings;
		EFI_HII_PACKAGE_HEADER end;
	} __attribute__ (( packed )) *package;

	/* Fail if any previous allocation failed */
	if ( ifr->failed )
		return NULL;

	/* Allocate package list */
	package = zalloc ( sizeof ( *package ) );
	if ( ! package )
		return NULL;

	/* Populate package list */
	package->header.PackageLength = sizeof ( *package );
	memcpy ( &package->header.PackageListGuid, guid,
		 sizeof ( package->header.PackageListGuid ) );
	package->ops.header.Length = sizeof ( package->ops );
	package->ops.header.Type = EFI_HII_PACKAGE_FORMS;
	memcpy ( package->ops.data, ifr->ops, sizeof ( package->ops.data ) );
	package->strings.header.header.Header.Length =
		sizeof ( package->strings );
	package->strings.header.header.Header.Type =
		EFI_HII_PACKAGE_STRINGS;
	package->strings.header.header.HdrSize =
		sizeof ( package->strings.header );
	package->strings.header.header.StringInfoOffset =
		sizeof ( package->strings.header );
	package->strings.header.header.LanguageName = language_id;
	strcpy ( package->strings.header.header.Language, language );
	memcpy ( package->strings.data, ifr->strings,
		 sizeof ( package->strings.data ) );
	package->strings.end.BlockType = EFI_HII_SIBT_END;
	package->end.Type = EFI_HII_PACKAGE_END;
	package->end.Length = sizeof ( package->end );

	return &package->header;
}

