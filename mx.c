#define IFDECO  if (options & MD_NO_DECORATION)
#define IFNDECO if (!(options & MD_NO_DECORATION))

#define MD_TTL_MEM	"Memory blocks:\n"
#define MD_TTL_MEM2	"Memory leaks:\n"

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
void md_display_valid_block(MD_Mem *blk, int options)
{
  int j;
  MD_Mem *m;

  /* allocation part */
  IFDECO
    {
    printf("%p %u \"%s\" \"%s:%d\"", blk->ptr, blk->size_a,
	       MD_DNAME(blk->func_a), MD_DFILE(blk->file_a), blk->line_a);
    }
  else
    {
    printf("Block %d\n", blk->block);
    printf("   alloc, size: %p,%-8u ", blk->ptr, blk->size_a);
    printf("%s (%s:%d)\n",
	       MD_DNAME(blk->func_a), MD_DFILE(blk->file_a), blk->line_a);
    md_display_stack(blk->nb_stack_a, blk->stack_a, options);
    }
  for (j=0, m=blk->rnext; m; m=m->rnext,j++);
  IFDECO
    printf(" %d\n", j);
  /* reallocation part */
  for (j=0, m=blk->rnext; m; m=m->rnext,j++)
    {
    IFDECO
      {
      printf("%p %u \"%s\" \"%s:%d\" ", m->ptr, m->size_a,
		   MD_DNAME(m->func_a), MD_DFILE(m->file_a), m->line_a);
      }
    else
      {
      printf("  realloc(%3d): %p,%-8u ", j+1, m->ptr, m->size_a);
      printf("%s (%s:%d)\n", MD_DNAME(m->func_a),
                   MD_DFILE(m->file_a), m->line_a);
      md_display_stack(m->nb_stack_a, m->stack_a, options);
      }
    if (!m->rnext)
    {
      j++;
      break;
    }
    }
  if (j > 0)
    IFDECO
      printf("\n");

  /* free part */
  if (!m)
    m = blk;
  if (m->where_f == NULL)
    {
    IFDECO
      printf("\"*\" \"*\"\n");
    else
      printf("     never freed.\n");
    }
  else
    {
    IFDECO
      printf("\"%s\" \"%s:%d\"\n",MD_DNAME(m->func_f),
                            MD_DFILE(m->file_f), m->line_f);
    else
      printf("      freed at:                    %s (%s:%d)\n",
      			    MD_DNAME(m->func_f),
                            MD_DFILE(m->file_f), m->line_f);
      md_display_stack(m->nb_stack_f, m->stack_f, options);
    }
}
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
    printf("   Leak, size: %p,%-8u ", blk->ptr, blk->size_a);
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

int md_display_leaks(int options)
{
  md_found_leak = 0;

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

  avl_apply(md_mems, (AVL_APPLY)md_display_leak1, (void *)(long)options, -1, AVL_INORDER);
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

int md_display_mem1(MD_Mem *me, int options)
{
  for (;me;me=me->anext)
  {
  if ((options & (MD_NO_UNRES_MALLOC|MD_NO_UNRES_REALLOC))&&
  	(me->where_a) && (!me->valid_a))
    continue;
  if ((options & MD_NO_UNRES_FREE)&&
  	(me->where_f) && (!me->valid_f))
    continue;

  /* This is a realloc, someone else will print it */
  if (me->rprev)
    continue;

  if (me->where_a)
    md_display_valid_block(me, options);
  else
    md_display_invalid_block(me, options);
  }
  return 0;
}

int md_display_memory(int options)
{
  if (!(options & MD_MORE))
    return(1);

  /** if requested, display memory usage details **/
  IFDECO
    {
    printf(">memory\n");
    }
  else
    {
    if (md_mems)
      {
      printf("\n");
      printf(MD_TTL_MEM);
      printf("\n");
      }
    }
  if (md_mems)
    avl_apply(md_mems, (AVL_APPLY)md_display_mem1, (void *)(long)options, -1, AVL_INORDER);
  else
  IFNDECO
    printf("\nNo memory block referenced.\n\n");
  IFDECO
    printf("<memory\n");
  return(1);
}
