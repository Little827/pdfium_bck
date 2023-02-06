#ifndef BASE_COMPONENT_EXPORT_H_
#define BASE_COMPONENT_EXPORT_H_

#ifdef SKIA_IMPLEMENTATION
#define COMPONENT_EXPORT(module) __attribute__((visibility("default")))
#else
#define COMPONENT_EXPORT(module)
#endif  // FPDF_IMPLEMENTATION

#endif  // BASE_COMPONENT_EXPORT_H_
