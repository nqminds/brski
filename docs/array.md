# Binary artifact API

The binary array APi defines the helper functions and structure to encode binary arrays and lists of binary arrays. The below structure and functions are used in the voucher and `BRSKI` protocol API as inputs and outputs.

## Voucher binary array
The array API defines a structure to encode binary arrays:
```c
struct BinaryArray {
  uint8_t *array;
  size_t length;
};
```
If `array == NULL` and `length == 0` the array is considered to be emtpy.

### `copy_binary_array`
Copies a binary arrays to a destination.

```c
int copy_binary_array(struct BinaryArray *const dst,
                      const struct BinaryArray *src);
```
**Parameters**:
* `dst` - The destination binary array and
* `src` - The source binary array.

**Return**:
`0` on success or `-1` on failure.

### `compare_binary_array`
Compare two binary arrays.

```c
int compare_binary_array(const struct BinaryArray *src,
                         const struct BinaryArray *dst);
```
**Parameters**:
* `src` - The source binary array and
* `dst` - The destination binary array.

**Return**:
`1` if arrays are equal, `0` otherwise or `-1` on failure.

### `free_binary_array_content`
Frees a binary array content, i.e., frees the `array` element of the `struct BinaryArray`.
```c
void free_binary_array_content(struct BinaryArray *arr);
```
**Parameters**:
* `arr` - The binary array

### `free_binary_array`
Frees a binary array structure and its content.
```c
void free_binary_array(struct BinaryArray *arr);
```
**Parameters**:
* `arr` - The binary array

### Buffer linked list definition

The `struct BinaryArrayList` is an array list that holds a pointer to a heap allocated array, the length and a generic flags integer.

```c
struct BinaryArrayList {
  uint8_t *arr;        /**< The array (heap allocated) */
  size_t length;       /**< The array length (heap allocated) */
  int flags;           /**< The generic array flags */
  struct dl_list list; /**< List definition */
};
```
**Parameters**:
* `arr` - pointer to the heap allocated array,
* `length` - the array length,
* `flags` - the generic array flags and
* `list` - the structure containg the previous and next element of the linked list.

### `init_array_list`
Initializes the array list.
```c
struct BinaryArrayList *init_array_list(void);
```

**Return**:
Initialised array list or `NULL` on failure.

### `free_array_list`
Frees the array list and all of its elements.
```c
void free_array_list(struct BinaryArrayList *arr_list);
```
**Parameters**:
* `arr_list` - The array list to free.

### `push_array_list`
Pushes a heap allocated array into the list and assigns the flags.
```c
int push_buffer_list(struct BinaryArrayList *arr_list,
                     uint8_t *const arr,
                     const size_t length,
                     const int flags);
```
**Parameters**:
* `arr_list` - The array list structure,
* `arr` - The array pointer to insert,
* `length` - The array length and
* `flags` - The array flags.

**Return**:
`0` on success or `-1` on failure.
