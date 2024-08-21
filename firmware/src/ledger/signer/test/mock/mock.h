/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2021 RSK Labs Ltd
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef __SIGNER_MOCK_H
#define __SIGNER_MOCK_H

// Nano S SDK constants used by the signer ux components
#define BAGL_FILL 1
#define BAGL_RECTANGLE 3
#define BAGL_LABELINE 7
#define BAGL_FONT_OPEN_SANS_REGULAR_11px 10
#define BAGL_FONT_ALIGNMENT_CENTER 0x8000

// Nano S SDK types used by the signer ux components
typedef struct {
    unsigned int type;
    unsigned char userid;
    short x;
    short y;
    unsigned short width;
    unsigned short height;
    unsigned char stroke;
    unsigned char radius;
    unsigned char fill;
    unsigned int fgcolor;
    unsigned int bgcolor;
    unsigned short font_id;
    unsigned char icon_id;
} mock_signer_ux_component_t;

typedef struct {
    mock_signer_ux_component_t component;
    const char *text;
    unsigned char touch_area_brim;
    int overfgcolor;
    int overbgcolor;
    const void *tap;
    const void *out;
    const void *over;
} mock_signer_ux_element_t;

typedef mock_signer_ux_element_t bagl_element_t;

// Nano S SDK functions and macros used by the signer ux components
void UX_DISPLAY(const mock_signer_ux_element_t *elements_array, void *callback);

#endif // __SIGNER_MOCK_H
