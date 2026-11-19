/* stand-in for Unity's mono-2.0-bdwgc.dll, to test the plumbing of C# -> C
 * on Windows: logs mono_jit_init_version and every internal call registered */
#include <stdio.h>
static int calls, icalls;
__declspec(dllexport) void *mono_jit_init_version(const char *name, const char *ver) {
    printf("mono: init %s %s\n", name, ver);
    return (void *)1;
}
__declspec(dllexport) void mono_add_internal_call(const char *name, const void *fn) {
    icalls++;
    if (icalls <= 3) printf("mono: internal call %s\n", name);
}
__declspec(dllexport) int fake_mono_icalls(void) { return icalls; }
__declspec(dllexport) void *mono_domain_get(void) { calls++; return 0; }
__declspec(dllexport) void *mono_get_corlib(void) { calls++; return 0; }
__declspec(dllexport) void *mono_image_loaded(void) { calls++; return 0; }
__declspec(dllexport) void *mono_image_get_name(void) { calls++; return 0; }
__declspec(dllexport) void *mono_assembly_name_new(void) { calls++; return 0; }
__declspec(dllexport) void *mono_assembly_name_free(void) { calls++; return 0; }
__declspec(dllexport) void *mono_assembly_load(void) { calls++; return 0; }
__declspec(dllexport) void *mono_assembly_get_image(void) { calls++; return 0; }
__declspec(dllexport) void *mono_class_get(void) { calls++; return 0; }
__declspec(dllexport) void *mono_class_from_name(void) { calls++; return 0; }
__declspec(dllexport) void *mono_class_init(void) { calls++; return 0; }
__declspec(dllexport) void *mono_class_vtable(void) { calls++; return 0; }
__declspec(dllexport) void *mono_runtime_class_init(void) { calls++; return 0; }
__declspec(dllexport) void *mono_vtable_get_static_field_data(void) { calls++; return 0; }
__declspec(dllexport) void *mono_class_value_size(void) { calls++; return 0; }
__declspec(dllexport) void *mono_class_get_element_class(void) { calls++; return 0; }
__declspec(dllexport) void *mono_class_enum_basetype(void) { calls++; return 0; }
__declspec(dllexport) void *mono_class_from_mono_type(void) { calls++; return 0; }
__declspec(dllexport) void *mono_class_get_type(void) { calls++; return 0; }
__declspec(dllexport) void *mono_class_get_image(void) { calls++; return 0; }
__declspec(dllexport) void *mono_class_is_valuetype(void) { calls++; return 0; }
__declspec(dllexport) void *mono_array_element_size(void) { calls++; return 0; }
__declspec(dllexport) void *mono_get_method(void) { calls++; return 0; }
__declspec(dllexport) void *mono_method_get_class(void) { calls++; return 0; }
__declspec(dllexport) void *mono_method_get_token(void) { calls++; return 0; }
__declspec(dllexport) void *mono_method_get_header(void) { calls++; return 0; }
__declspec(dllexport) void *mono_method_header_get_locals(void) { calls++; return 0; }
__declspec(dllexport) void *mono_method_signature(void) { calls++; return 0; }
__declspec(dllexport) void *mono_signature_get_params(void) { calls++; return 0; }
__declspec(dllexport) void *mono_method_desc_new(void) { calls++; return 0; }
__declspec(dllexport) void *mono_method_desc_search_in_class(void) { calls++; return 0; }
__declspec(dllexport) void *mono_method_desc_free(void) { calls++; return 0; }
__declspec(dllexport) void *mono_field_from_token(void) { calls++; return 0; }
__declspec(dllexport) void *mono_field_get_parent(void) { calls++; return 0; }
__declspec(dllexport) void *mono_field_get_offset(void) { calls++; return 0; }
__declspec(dllexport) void *mono_object_new(void) { calls++; return 0; }
__declspec(dllexport) void *mono_array_new(void) { calls++; return 0; }
__declspec(dllexport) void *mono_array_length(void) { calls++; return 0; }
__declspec(dllexport) void *mono_array_addr_with_size(void) { calls++; return 0; }
__declspec(dllexport) void *mono_object_get_class(void) { calls++; return 0; }
__declspec(dllexport) void *mono_object_isinst(void) { calls++; return 0; }
__declspec(dllexport) void *mono_value_box(void) { calls++; return 0; }
__declspec(dllexport) void *mono_object_unbox(void) { calls++; return 0; }
__declspec(dllexport) void *mono_ldstr(void) { calls++; return 0; }
__declspec(dllexport) void *mono_gchandle_new(void) { calls++; return 0; }
__declspec(dllexport) void *mono_object_get_virtual_method(void) { calls++; return 0; }
__declspec(dllexport) void *mono_runtime_invoke(void) { calls++; return 0; }
__declspec(dllexport) void *mono_type_get_object(void) { calls++; return 0; }
__declspec(dllexport) void *mono_method_get_object(void) { calls++; return 0; }
__declspec(dllexport) void *mono_gc_wbarrier_set_field(void) { calls++; return 0; }
__declspec(dllexport) void *mono_gc_wbarrier_set_arrayref(void) { calls++; return 0; }
__declspec(dllexport) void *mono_gc_wbarrier_generic_store(void) { calls++; return 0; }
__declspec(dllexport) void *mono_gc_wbarrier_value_copy(void) { calls++; return 0; }
__declspec(dllexport) void *mono_raise_exception(void) { calls++; return 0; }
__declspec(dllexport) void *mono_exception_from_name(void) { calls++; return 0; }
__declspec(dllexport) void *mono_get_exception_null_reference(void) { calls++; return 0; }
__declspec(dllexport) void *mono_get_exception_divide_by_zero(void) { calls++; return 0; }
__declspec(dllexport) void *mono_get_exception_overflow(void) { calls++; return 0; }
__declspec(dllexport) void *mono_get_exception_index_out_of_range(void) { calls++; return 0; }
__declspec(dllexport) void *mono_get_exception_invalid_cast(void) { calls++; return 0; }
__declspec(dllexport) void *mono_get_exception_array_type_mismatch(void) { calls++; return 0; }
__declspec(dllexport) void *mono_get_exception_arithmetic(void) { calls++; return 0; }
