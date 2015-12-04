/* malloc tracer for memory leak tracking
 * This fragment actually prints the leak report
 * -- Howard Chu, hyc@symas.com 2015-03-24
 */
#define IFDECO  if (options & MD_NO_DECORATION)
#define IFNDECO if (!(options & MD_NO_DECORATION))

#define MD_TTL_MEM	"Memory blocks:\n"
#define MD_TTL_MEM2	"Memory leaks (%ld total):\n", md_nb_mem_used

void md_display_stack(int nb_stack, MD_Loc *stack, int options)
{
  int l;

  if (nb_stack == 0)
    return;

  IFDECO
    printf("stack ");
  for(l=1; l<nb_stack; l++)
    {
    if (stack[l].addr == NULL)
      {
      IFDECO
        printf("\"*\" ");
      }
    else
      {
      IFDECO
        {
	if (options & MD_MEMORY_LINE)
	  printf("\"%s\" \"%s:%d\" \"%s\" ", MD_DNAME(stack[l].name), MD_DFILE(stack[l].file),
	                          stack[l].line, MD_DOBJ(stack[l].object));
	printf("\"%s\" ", MD_DNAME(stack[l].name));
	}
      else
	{
	if (l == 1)
	  printf("     stack: ");
	if (options & MD_MEMORY_LINE)
	{
	  if (l>1)
	    printf("            ");
	  printf("%20s : %s (%s:%d)\n", MD_DOBJ(stack[l].object),
	    MD_DNAME(stack[l].name), MD_DFILE(stack[l].file), stack[l].line);
	}else
	{
	  if (l>1)
	    printf(" <- ");
  	  printf("%s", MD_DNAME(stack[l].name));
	  if (l+1 == nb_stack || stack[l+1].addr == NULL)
	    printf("\n");
	}
	}
      }
    }
  IFDECO
    printf("\n");
}



/* sub-functions used by memory_leaks and memory_blocks */
void md_display_invalid_block(MD_Mem *blk, int options)
{
  if (blk->anext && blk->anext->where_f)
    {
    IFDECO
      {
      printf("still %p \"%s\" \"%s:%d\" \"%s\" \"%s:%d\"\n",
	 blk->ptr, MD_DNAME(blk->func_f),
	 MD_DFILE(blk->file_f), blk->line_f,
	 MD_DNAME(blk->anext->func_f),
	 MD_DFILE(blk->anext->file_f),
	 blk->anext->line_f);
      }
    else
      printf("Manipulation of address %p at %s (%s:%d),"
	     "    which was freed at %s (%s:%d)\n",
	 blk->ptr, MD_DNAME(blk->func_f),
	 MD_DFILE(blk->file_f), blk->line_f,
	 MD_DNAME(blk->anext->func_f),
	 MD_DFILE(blk->anext->file_f),
	 blk->anext->line_f);
    }
  else
  if (blk->func_a == NULL)
    {/* invalid free */
    IFDECO
      printf("free %p \"%s\" \"%s:%d\"\n",
		blk->ptr, MD_DNAME(blk->func_f),
        	MD_DFILE( blk->file_f), blk->line_f);
    else
      printf("   unreferenced address (%p) for 'free' at %s (%s:%d)\n",
		blk->ptr, MD_DNAME(blk->func_f),
        	MD_DFILE( blk->file_f), blk->line_f);
    }
  else
    {/* invalid realloc */
    IFDECO
      printf("realloc %p \"%s\" \"%s:%d\"\n", 
		blk->ptr, MD_DNAME(blk->func_f),
        	MD_DFILE(blk->file_f), blk->line_f);
    else
      printf("   unreferenced address (%p) for 'realloc' at %s (%s:%d)\n",
		blk->ptr, MD_DNAME(blk->func_f),
        	MD_DFILE(blk->file_f), blk->line_f);
    }
}
void md_display_valid_leak(MD_Mem *blk, int options)
{
  int j;
  MD_Mem *m;

  for (j=0,m=blk->rnext;m;m=m->rnext,j++);
  /* normal behavior */
  IFDECO
    {
    printf("%p %u \"%s\" \"%s:%d\" %d\n",blk->ptr, blk->size_a,
	     MD_DNAME(blk->func_a), MD_DFILE(blk->file_a), blk->line_a,
	     j);
    }
  else
    {
    printf("   Leak, blocks, size: %p,%d,%-8u ", blk->ptr, blk->block, blk->size_a);
    printf(" %s (%s:%d)\n", MD_DNAME(blk->func_a),
                                       MD_DFILE(blk->file_a), blk->line_a);
    }
  /*call-stack */
  md_display_stack(blk->nb_stack_a, blk->stack_a, options);
  for (j=0,m=blk->rnext;m;m=m->rnext,j++)
    {
    IFDECO
      {
      printf("%p %u \"%s\" \"%s:%d\"\n", m->ptr, m->size_a,
          MD_DNAME(m->func_a),MD_DFILE(m->file_a),m->line_a);
      }
    else
      {
      printf("   realloc(%3d): %p,%-8u ", j+1, m->ptr, m->size_a);
      printf(" %s (%s:%d)\n",
          MD_DNAME(m->func_a),MD_DFILE(m->file_a),m->line_a);
      }
    /* new: call-stack */
    md_display_stack(m->nb_stack_a, m->stack_a, options);
    }
  if (j > 0)
    IFDECO
      printf("\n");
}

static int md_found_leak;

int md_display_leak1(MD_Mem *me, int options)
{
  for (;me;me=me->anext)
  {
  if ((options & (MD_NO_UNRES_MALLOC|MD_NO_UNRES_REALLOC))&&
  	(me->where_a) && (!me->valid_a))
    continue;
  if ((options & MD_NO_UNRES_FREE)&&
  	(me->where_f) && (!me->valid_f))
    continue;

  if (me->where_a)
  {
    if (!me->where_f && !me->rnext)
    {
      if (!md_found_leak)
      {
        md_found_leak = 1;
        IFNDECO
        {
          printf("\n");
          printf(MD_TTL_MEM2);
          printf("\n");
        }
      }
      md_display_valid_leak(me, options);
    }
  }
  else
  {
    if (!md_found_leak)
    {
      md_found_leak = 1;
      IFNDECO
      {
        printf("\n");
        printf(MD_TTL_MEM2);
        printf("\n");
      }
    }
    md_display_invalid_block(me, options);
  }
  }
  return 0;
}

MD_Mem **leaks;
int lcnt;

int md_linearize_leaks(MD_Mem *me, int foo)
{
	leaks[lcnt++] = me;
	return 0;
}

/* sort in descending order of size, #blocks */
int md_sort_leaks(const void *v1, const void *v2)
{
	MD_Mem **p1 = (MD_Mem **)v1, **p2 = (MD_Mem **)v2;
	MD_Mem *m1 = *p1, *m2 = *p2;
	long l;

	l = (long)m2->size_a - (long)m1->size_a;
	if (l)
		return l < 0 ? -1 : l > 0;
	return m2->block - m1->block;
}

int md_display_leaks(int options)
{
  md_found_leak = 0;
  int i;

  leaks = malloc(blocks * sizeof(MD_Mem));
  avl_apply(md_mems, (AVL_APPLY)md_linearize_leaks, NULL, -1, AVL_INORDER);
  qsort(leaks, blocks, sizeof(MD_Mem *), md_sort_leaks);

  if (!md_mems)
    {
    IFDECO
      {
      printf(">leaks\n");
      printf("<leaks\n");
      }
    else
      printf("\nNo memory leaks (no memory block referenced).\n\n");
    return(1);
    }
  IFDECO
    printf(">leaks\n");

  for (i=0; i<blocks; i++)
	md_display_leak1(leaks[i], options);
  IFNDECO
    {
    if (!md_found_leak)
      {
      printf("\nNo memory leaks.\n\n");
      }
    }
  IFDECO
    printf("<leaks\n");

  return(1);
}

