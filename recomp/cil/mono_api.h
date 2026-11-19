/* The part of Mono's public embedding API that cil2c's C code uses, declared
 * here so the translated C builds without Mono's headers (Unity games ship
 * mono-2.0-bdwgc.dll but no headers). Names and types follow Mono's own
 * headers; on Windows these are imported from the game's Mono DLL. */
#pragma once
#include <stdint.h>

typedef int32_t mono_bool;
typedef struct _MonoDomain MonoDomain;
typedef struct _MonoImage MonoImage;
typedef struct _MonoAssembly MonoAssembly;
typedef struct _MonoAssemblyName MonoAssemblyName;
typedef struct _MonoClass MonoClass;
typedef struct _MonoMethod MonoMethod;
typedef struct _MonoClassField MonoClassField;
typedef struct _MonoType MonoType;
typedef struct MonoVTable MonoVTable;
typedef struct MonoMethodSignature MonoMethodSignature;
typedef struct _MonoMethodHeader MonoMethodHeader;
typedef struct MonoMethodDesc MonoMethodDesc;
typedef struct _MonoReflectionType MonoReflectionType;
typedef struct _MonoReflectionMethod MonoReflectionMethod;
/* object header: vtable + sync block (instance fields start right after) */
typedef struct _MonoObject { void *vtable; void *synchronisation; } MonoObject;
typedef struct _MonoArray MonoArray;
typedef struct _MonoString MonoString;
typedef struct _MonoException MonoException;
typedef int MonoImageOpenStatus;

#ifdef _WIN32
#define CIL_MONO_IMPORT __declspec(dllimport)
#else
#define CIL_MONO_IMPORT
#endif
#define M CIL_MONO_IMPORT

M MonoDomain *mono_domain_get(void);
M MonoImage *mono_get_corlib(void);
M MonoImage *mono_image_loaded(const char *name);
M const char *mono_image_get_name(MonoImage *image);
M MonoAssemblyName *mono_assembly_name_new(const char *name);
M void mono_assembly_name_free(MonoAssemblyName *aname);
M MonoAssembly *mono_assembly_load(MonoAssemblyName *aname, const char *basedir, MonoImageOpenStatus *status);
M MonoImage *mono_assembly_get_image(MonoAssembly *assembly);

M MonoClass *mono_class_get(MonoImage *image, uint32_t type_token);
M MonoClass *mono_class_from_name(MonoImage *image, const char *name_space, const char *name);
M mono_bool mono_class_init(MonoClass *klass);
M MonoVTable *mono_class_vtable(MonoDomain *domain, MonoClass *klass);
M void mono_runtime_class_init(MonoVTable *vtable);
M void *mono_vtable_get_static_field_data(MonoVTable *vt);
M int32_t mono_class_value_size(MonoClass *klass, uint32_t *align);
M MonoClass *mono_class_get_element_class(MonoClass *klass);
M MonoType *mono_class_enum_basetype(MonoClass *klass);
M MonoClass *mono_class_from_mono_type(MonoType *type);
M MonoType *mono_class_get_type(MonoClass *klass);
M MonoImage *mono_class_get_image(MonoClass *klass);
M mono_bool mono_class_is_valuetype(MonoClass *klass);
M int32_t mono_array_element_size(MonoClass *ac);

M MonoMethod *mono_get_method(MonoImage *image, uint32_t token, MonoClass *klass);
M MonoClass *mono_method_get_class(MonoMethod *method);
M uint32_t mono_method_get_token(MonoMethod *method);
M MonoMethodHeader *mono_method_get_header(MonoMethod *method);
M MonoType **mono_method_header_get_locals(MonoMethodHeader *header, uint32_t *num_locals, mono_bool *init_locals);
M MonoMethodSignature *mono_method_signature(MonoMethod *method);
M MonoType *mono_signature_get_params(MonoMethodSignature *sig, void **iter);
M MonoMethodDesc *mono_method_desc_new(const char *name, mono_bool include_namespace);
M MonoMethod *mono_method_desc_search_in_class(MonoMethodDesc *desc, MonoClass *klass);
M void mono_method_desc_free(MonoMethodDesc *desc);

M MonoClassField *mono_field_from_token(MonoImage *image, uint32_t token, MonoClass **retklass, void *context);
M MonoClass *mono_field_get_parent(MonoClassField *field);
M uint32_t mono_field_get_offset(MonoClassField *field);

M MonoObject *mono_object_new(MonoDomain *domain, MonoClass *klass);
M MonoArray *mono_array_new(MonoDomain *domain, MonoClass *eclass, uintptr_t n);
M uintptr_t mono_array_length(MonoArray *array);
M char *mono_array_addr_with_size(MonoArray *array, int size, uintptr_t idx);
M MonoClass *mono_object_get_class(MonoObject *obj);
M MonoObject *mono_object_isinst(MonoObject *obj, MonoClass *klass);
M MonoObject *mono_value_box(MonoDomain *domain, MonoClass *klass, void *val);
M void *mono_object_unbox(MonoObject *obj);
M MonoString *mono_ldstr(MonoDomain *domain, MonoImage *image, uint32_t str_index);
M uint32_t mono_gchandle_new(MonoObject *obj, mono_bool pinned);
M MonoMethod *mono_object_get_virtual_method(MonoObject *obj, MonoMethod *method);
M MonoObject *mono_runtime_invoke(MonoMethod *method, void *obj, void **params, MonoObject **exc);
M MonoReflectionType *mono_type_get_object(MonoDomain *domain, MonoType *type);
M MonoReflectionMethod *mono_method_get_object(MonoDomain *domain, MonoMethod *method, MonoClass *refclass);

M void mono_gc_wbarrier_set_field(MonoObject *obj, void *field_ptr, MonoObject *value);
M void mono_gc_wbarrier_set_arrayref(MonoArray *arr, void *slot_ptr, MonoObject *value);
M void mono_gc_wbarrier_generic_store(void *ptr, MonoObject *value);
M void mono_gc_wbarrier_value_copy(void *dest, void *src, int count, MonoClass *klass);

M void mono_add_internal_call(const char *name, const void *method);
M void mono_raise_exception(MonoException *ex);
M MonoException *mono_exception_from_name(MonoImage *image, const char *name_space, const char *name);
M MonoException *mono_get_exception_null_reference(void);
M MonoException *mono_get_exception_divide_by_zero(void);
M MonoException *mono_get_exception_overflow(void);
M MonoException *mono_get_exception_index_out_of_range(void);
M MonoException *mono_get_exception_invalid_cast(void);
M MonoException *mono_get_exception_array_type_mismatch(void);
M MonoException *mono_get_exception_arithmetic(void);
#undef M
