/** used MACROS and other DEFINES **/
/* the MAX/MIN macro */
#define MD_MAX(a,b)  (((a)>(b))?(a):(b))
#define MD_MIN(a,b)  (((a)<(b))?(a):(b))
#define ABS(v) ((v)<0?-(v):(v))
/* macros to display (potentially null) names */
/* function name */
#define MD_DNAME(n)  (((n)==NULL)?"??":(n))
/* file */
#define MD_DFILE(n)  (((n)==NULL)?"??":(n))
/* object */
#define MD_DOBJ(n)   (((n)==NULL)?"??.so":(n))
/* string buffers */
#define MD_MAX_BUFFER 1024

#define MD_MORE	1
#define MD_NO_DEMANGLE	2
#define MD_FULLNAME	4
#define MD_NO_DECORATION	8
#define MD_MEMORY_LINE	0x10
#define MD_NO_UNRES_MALLOC	0x20
#define MD_NO_UNRES_REALLOC	0x40
#define MD_NO_UNRES_FREE	0x80

/* Description of a function or call address */
/* This structure is overlaid on some of the others. */
typedef struct
{
   void *addr;		/* address of event */
   char *name;		/* name of function containing address */
   char *object;	/* path to object containing address */
   char *file;		/* source file containing the function */
   int line;		/* line number in source file */
   int valid;		/* is this name ok? */
}MD_Loc;

typedef struct MD_Mem
{
  void *ptr;
  unsigned int size_a;
  unsigned int block;

  void *where_a;   /* allocation place */
  char *func_a;    /* corresp. function */
  char *object_a;    /* corresp. object */
  char *file_a;    /* corresp. file:line */
  int line_a;
  int valid_a;

  /* call stack */
  MD_Loc *stack_a;
  unsigned int nb_stack_a;

  void *where_f;   /* freeing place */
  char *func_f;    /* corresp. function */
  char *object_f;  /* corresp. object */
  char *file_f;    /* corresp. file:line */
  int line_f;
  int valid_f;

  /* stack at the free */
  MD_Loc *stack_f;
  unsigned int nb_stack_f;

  struct MD_Mem *rnext;	/* realloc list */
  struct MD_Mem *rprev;	/* prior alloc */
  struct MD_Mem *anext;	/* next at this addr */
}MD_Mem;

/* a dynamic object */
typedef struct
{
  void *base;
  char path[1];
}MD_DynObj;

/** variables **/
extern int md_nobjects;
extern MD_DynObj **md_objects;

extern Avlnode *md_mems;
