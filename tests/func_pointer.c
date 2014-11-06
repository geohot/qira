int twice(int x)
{
	return 2*x;
}

int main ()
{
	int (*fptr)(int);
	fptr = &twice;
	return (*fptr)(4);
}
