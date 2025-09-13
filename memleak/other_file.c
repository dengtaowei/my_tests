

void * other_file_malloc(int size)
{
    void *ptr = malloc(size);
    if (size % 2 == 0)
    {
        free(ptr);
    }
    return 0;
}

void other_file_free(void *ptr)
{
    free(ptr);
}