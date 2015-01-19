int quad(int x)
{
	return x*4;
}

int (*quad_ptr)(int);

int main()
{
	quad_ptr = &quad;
	return (*quad_ptr)(3);
}
