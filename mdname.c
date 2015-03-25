/* malloc tracer for memory leak tracking
 * This file contains routines to map addresses to object files,
 * symbol names, and source locations.
 * -- Howard Chu, hyc@symas.com 2015-03-24
 */
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>

#include <bfd.h>

/* FIXME: this file is in the current directory, but is a part of
   binutils. But binutils don't installs it in standard include/
   directory! (needed for function cplus_demangle()) */
#include "demangle.h"

#include "avl.h"
#include "mdump.h"

/* texts for special values (functions, files...) */
char *md_ndef_function="<unknown_fnc>";
char *md_ndef_file="<unknown_file>";
char *md_ndef_object="<unknown_obj>";
char *md_mem_function="<merror_fnc>";
char *md_mem_file="<merror_file>";
char *md_mem_object="<merror_obj>";
char *md_before_function="<system_b>";
char *md_after_function="<system_a>";
char *md_baddr_function="<sys-:%p>";
char *md_aaddr_function="<sys+:%p>";
char *md_err_memory="<merror>";
char *md_err_ndef="<error>";



/* struct to keep track of names for demangling purposes */
typedef struct
{
  char *name;
  int done;
}MDNym;

/* address of a line of a function */
typedef struct
{
  void *addr;
  unsigned int line;
}MDLin;

/* temp structure to extract names from .so files */
typedef struct
{
  void *addr;
  char *name;
  char *file;
  MDLin *lines;
  int nb_lines;
  flagword flag;  /* corresponding flag */
  MDNym *xname;
}MDSym;
MDSym *md_syms=NULL;
int md_nb_syms=0;


/* this structure is devoted to contains each address of
   symbols to be treated. corresponding name, file and line
   are specified here, in order to be updated by the program */
typedef struct
{
  MD_Loc *loc;
  MDNym *xname;	  /* address of master name ptr */
  int done;
}HXRequest;


/* add an entry to the request list */
HXRequest* md_add_request(HXRequest *reqlist, int *nb, MD_Loc *loc)
{
  if (*nb == 0)
    {
    reqlist = malloc(sizeof(HXRequest));
    }
  else
    {
    reqlist = realloc(reqlist, sizeof(HXRequest)*((*nb)+1));
    }
  if (reqlist == NULL)
    {
    fprintf(stderr, "Out of memory in name extraction\n");
    return(NULL);
    }

  loc->name = NULL;
  loc->object = NULL;
  loc->file = NULL;
  loc->line = 0;
  loc->valid = 0;

  reqlist[*nb].loc = loc;
  reqlist[*nb].done = 0;
  reqlist[*nb].xname = NULL;

  (*nb)++;
  return(reqlist);
}



/* return pointer on beginning of file basename */
char *md_get_basename(char *name)
{
  char *ptr;

  if (name == NULL)
    return(NULL);
  if (name[0] == 0)
    return(name);
  /* return the 1st '/' from the end */
  ptr = strrchr(name, '/');
  if (ptr && ptr[1])
    return ptr+1;
  return(name);
}


/* add a 'm' before the name */
int md_compute_new_name(char *buf, char *oname)
{
  int i;

  /* search for the '/' (if exist) */
  for(i=strlen(oname)-1; i>=0; i--)
    {
    if (oname[i] == '/')
      break;
    }
  /* no '/'. just do m%s */
  if (oname[i] != '/')
    {
    sprintf(buf, "m%s", oname);
    return(1);
    }
  /* copy the starting elements */
  strncpy(buf, oname, i+1);
  buf[i+1] = '\0';
  strcat(buf, "m");
  strcat(buf, &(oname[i+1]));
  return(1);
}

void md_demangle(MDNym *xname, int options)
{
  char *tmp;

  if (xname->done)
    return;
  xname->done = 1;
  if (options & MD_NO_DEMANGLE)
    return;
  tmp = cplus_demangle(xname->name, DMGL_ANSI | DMGL_PARAMS);
  if (tmp && tmp != xname->name)
    {
    free(xname->name);
    xname->name = tmp;
    }
}

int md_open_bfd_file(char *name, bfd **core_bfd, int *core_num_syms,
                     asection **core_text_sect, asymbol ***core_syms,
		     int *core_min_insn_size, int *core_offset_to_code)
{
  *core_bfd = bfd_openr(name, 0);
  if (!(*core_bfd))
    {
    fprintf(stderr, "fncdump: Cant open %s\n", name);
    return(0);
    }
  /* check format */
  if (!bfd_check_format(*core_bfd, bfd_object))
    {
    fprintf(stderr, "fncdump: File %s is not an object.", name);
    return(0);
    }
  /* get TEXT section */
  *core_text_sect = bfd_get_section_by_name(*core_bfd, ".text");
  if (!(*core_text_sect))
    {
    *core_text_sect = bfd_get_section_by_name (*core_bfd, "$CODE$");
    if (!(*core_text_sect))
      {
      fprintf(stderr, "fncdump: No TEXT section in object %s.\n", name);
      return(0);
      }
    }
  /* read symbol table */
  *core_num_syms = bfd_get_symtab_upper_bound(*core_bfd);
  if (*core_num_syms < 0)
    {
    fprintf(stderr, "fncdump: %s\n", bfd_errmsg(bfd_get_error()));
    return(0);
    }
  *core_syms = (asymbol **) malloc(sizeof(asymbol*)*(*core_num_syms));
  if (*core_syms == NULL)
    {
    fprintf(stderr, "fncdump: Memory error while allocating %d bytes.\n", (int)sizeof(asymbol*)*(*core_num_syms));
    fprintf(stderr, "fncdump: Fatal error!\n");
    exit(9);
    }
  *core_num_syms = bfd_canonicalize_symtab(*core_bfd, *core_syms);
  if (*core_num_syms < 0)
    {
    free(*core_syms);
    fprintf(stderr, "fncdump: %s\n", bfd_errmsg(bfd_get_error()));
    return(0);
    }
  *core_min_insn_size = 1;
  *core_offset_to_code = 0;
  switch (bfd_get_arch(*core_bfd))
    {
    case bfd_arch_vax:
    case bfd_arch_tahoe:
      *core_offset_to_code = 2;
      break;
    case bfd_arch_alpha:
      *core_min_insn_size = 4;
      break;
    default:
      break;
    }
  return(1);
}

int md_compare_names(const void *e1, const void *e2)
{
  char *n1 = ((MDSym *)e1)->name;
  char *n2 = ((MDSym *)e2)->name;
  if (!n1) n1 = "";
  if (!n2) n2 = "";
  return strcmp(n1, n2);
}
int md_compare_pointers(const void *e1, const void *e2)
{
  long l = ((MDSym*)e1)->addr - ((MDSym*)e2)->addr;
  return l < 0 ? -1 : l > 0;
}

/* sort in descending order */
int md_compare_dynobj(const void *e1, const void *e2)
{
	MD_DynObj **d1 = (MD_DynObj **)e1, **d2 = (MD_DynObj **)e2;
	long l = (*d2)->base - (*d1)->base;
  return l < 0 ? -1 : l > 0;
}

int md_init_extract_dynamic(int core_num_syms, asymbol **core_syms, int sortn)
{
  int i, j;

  if ((md_syms = malloc(sizeof(MDSym)*core_num_syms)) == NULL)
    {
    fprintf(stderr, "fncdump: Recoverable memory error.\n");
    return(0);
    }
  /* put addr/names in table */
  for(i=0,j=0; i<core_num_syms; i++)
    {
    if (core_syms[i]->flags & BSF_FILE) continue;
    md_syms[j].name = (char*)bfd_asymbol_name(core_syms[i]);
    md_syms[j].addr = (void*)bfd_asymbol_value(core_syms[i]);
    md_syms[j].flag = core_syms[i]->flags;
    md_syms[j].xname = NULL;
    md_syms[j].lines = NULL;
    md_syms[j].nb_lines = 0;
    md_syms[j].file = NULL;
#if 0
printf("%p %s ", md_syms[j].addr, md_syms[j].name ? md_syms[j].name : "??");
if (core_syms[i]->flags & BSF_GLOBAL)
  printf("BFD_GLOBAL ");
if (core_syms[i]->flags & BSF_LOCAL)
  printf("BSF_LOCAL ");
if (core_syms[i]->flags & BSF_FUNCTION)
  printf("BSF_FUNCTION ");
if (core_syms[i]->flags & BSF_WEAK)
  printf("BSF_WEAK ");
if (core_syms[i]->flags & BSF_INDIRECT)
  printf("BSF_INDIRECT ");
if (core_syms[i]->flags & BSF_FILE)
  printf("BSF_FILE ");
if (core_syms[i]->flags & BSF_DYNAMIC)
  printf("BSF_DYNAMIC ");
if (core_syms[i]->flags & BSF_OBJECT)
  printf("BSF_OBJECT ");
printf("\n");
#endif
    j++;
    }
  md_nb_syms = j; /* core_num_syms; */
  /* sort it by pointer value */
  if (sortn)
    qsort(md_syms, md_nb_syms, sizeof(MDSym), md_compare_pointers);
  else
    qsort(md_syms, md_nb_syms, sizeof(MDSym), md_compare_names);
  return(1);
}
int md_fini_extract_dynamic()
{
  if (md_syms != NULL)
    free(md_syms);
  md_syms = NULL;
  md_nb_syms = 0;
  return(1);
}
int md_extract_dynamic(HXRequest *req, int *idx)
{
  int i, lo, hi;
  char *tmp, buffer[1024];

  req->loc->valid = 0;
  if (md_syms == NULL)
    return(0);
  if (req->loc->addr < md_syms[0].addr ||
      req->loc->addr > md_syms[md_nb_syms-1].addr)
    return(0);
  /* I may use a better search method :o) */
  /* Uses binsearch now! */
  for (lo=0, hi=md_nb_syms-1; lo<=hi;)
    {
    i = (lo+hi) >> 1;
    if ((req->loc->addr >= md_syms[i].addr) &&
        (req->loc->addr < md_syms[i+1].addr))
      {
      if (!md_syms[i].xname)
        {
	md_syms[i].xname = (MDNym *)malloc(sizeof(MDNym));
	md_syms[i].name = strdup(md_syms[i].name);
	md_syms[i].xname->name = md_syms[i].name;
	md_syms[i].xname->done = 0;
	}
      req->xname = md_syms[i].xname;
      req->loc->name = md_syms[i].name;
      req->loc->valid = 1;
      *idx = i;
      return(1);
      }
      if (md_syms[i].addr > req->loc->addr)
        hi = i-1;
      else
        lo = i+1;
    }
  /* may not occur */
  return(0);
}

static char **files;
static int numfiles;

char *md_dup_file(char *file, int options)
{
  int lo, hi, i, j;

  if (file == NULL)
    return md_ndef_file;

  for (j=1, i=0, lo=0, hi=numfiles-1; lo<=hi;)
    {
    i = (lo+hi) >> 1;
    j = strcmp(files[i], file);
    if (j == 0)
      break;
    if (j>0)
      hi = i-1;
    else
      lo = i+1;
    }
  if (j)
    {
    files = realloc(files, (numfiles+1)*sizeof(char *));
    file = strdup(file);
    if (i>0 && j>0)
      --i;
    for (j=numfiles;j>i;j--)
      files[j] = files[j-1];
    files[j] = file;
    numfiles++;
    }
  file = files[i];
  if (!(options & MD_FULLNAME))
    return md_get_basename(file);
  else
    return file;
}
char *md_set_object(char *obj, int options)
{
  if (obj == NULL)
    return(md_ndef_object);
  if (!(options & MD_FULLNAME))
    return md_get_basename(obj);
  else
    return obj;
}

void md_find_line(bfd *core_bfd, asection *core_text_sect,
	asymbol **core_syms, bfd_vma vaddr,HXRequest *req,int sym,int options)
{
  int i;

  for (i=0;i<md_syms[sym].nb_lines;i++)
    {
    if (md_syms[sym].lines[i].addr == req->loc->addr)
      break;
    }
  if (i == md_syms[sym].nb_lines)
    {
    char *file, *func;

    md_syms[sym].lines = realloc(md_syms[sym].lines,
      (md_syms[sym].nb_lines+1)*sizeof(MDLin));
    md_syms[sym].nb_lines++;
    md_syms[sym].lines[i].addr = req->loc->addr;
    bfd_find_nearest_line(core_bfd, core_text_sect, core_syms,
			  (bfd_vma)vaddr - core_text_sect->vma,
			  (const char**)&file, (const char**)&func,
			  &md_syms[sym].lines[i].line);
    if (file && !md_syms[sym].file)
      md_syms[sym].file = md_dup_file(file, options);
    }
  req->loc->file = md_syms[sym].file;
  req->loc->line = md_syms[sym].lines[i].line;
}

static int nb_reqlist;

int md_add_memreq(MD_Mem *me, HXRequest **reqlist)
{
  int i;

  for(;me;me=me->anext)
  {
    if (me->where_a != NULL)
      {
      *reqlist = md_add_request(*reqlist, &nb_reqlist,
                               (MD_Loc *)&me->where_a);
      }
    if (me->where_f != NULL)
      {
      *reqlist = md_add_request(*reqlist, &nb_reqlist,
                               (MD_Loc *)&me->where_f);
      }
    /* names for memory stack */
    for(i=1; i<me->nb_stack_a; i++)
      {
      if (me->stack_a[i].addr == NULL)
	break;
      *reqlist = md_add_request(*reqlist, &nb_reqlist,
                               &me->stack_a[i]);
      }
    for(i=1; i<me->nb_stack_f; i++)
      {
      if (me->stack_f[i].addr == NULL)
	break;
      *reqlist = md_add_request(*reqlist, &nb_reqlist,
                               &me->stack_f[i]);
      }
  }
  return 0;
}

/* extract functions name from symbol addresses */
/* options: options of fncdump
   exec:    the executable name
*/
int md_extract_names(int options, char *exec)
{
  int i, j, k;
  HXRequest *reqlist=NULL;
  char buffer[1024], tmpdir[1024];
  /* BFD data for exec */
  bfd *core_bfd;
  int core_min_insn_size;
  int core_offset_to_code;
  asection *core_text_sect;
  int core_num_syms;
  asymbol **core_syms;
  /* temp data */
  char *func_name;
  char *file_name;
  unsigned int line;
  int not_all_done=0, valid;
  char *object;

  /* read names for memory tracking */
  avl_apply(md_mems, (AVL_APPLY)md_add_memreq, (void *)&reqlist, -1,
  	AVL_INORDER);

  /* now open the executable */
  if (!md_open_bfd_file(exec, &core_bfd, &core_num_syms,
                        &core_text_sect, &core_syms,
			&core_min_insn_size, &core_offset_to_code))
    {
    if (reqlist != NULL)
      free(reqlist);
    return(0);
    }
  /* we extract function names with our method, and after we extract
     the file:line information. */
  md_init_extract_dynamic(core_num_syms, core_syms, 1);
  object = md_set_object(exec, options);
  for(i=0; i<nb_reqlist; i++)
    {
    /* Did we get a valid address, and is it a definition? */
    if (md_extract_dynamic(&reqlist[i], &j) &&
        (md_syms[j].flag & (BSF_GLOBAL|BSF_LOCAL)))
      {
      reqlist[i].loc->object = object;
      reqlist[i].done = 1;
      md_find_line(core_bfd,core_text_sect,core_syms,(bfd_vma)reqlist[i].loc->addr,
      		   &reqlist[i],j,options);
      }
    else
      not_all_done = 1;
    }
  md_fini_extract_dynamic();
  /* close this bfd */
  bfd_close(core_bfd);
  free(core_syms);

  /* some symbols are not completed */
  /* the best way, here, would be to obtain the object name from
     where the symbol comes... as I dont know how to do that,
     I search in all objects */
  if (not_all_done && md_nobjects)
    {
    /* Sort the objects in descending order */
    qsort(md_objects, md_nobjects, sizeof(MD_DynObj*), md_compare_dynobj);

    for (k=0; not_all_done && k<md_nobjects; k++)
      {
	  if (!md_objects[k]->path[0]) continue;
      /* now open the object */
      if (!md_open_bfd_file(md_objects[k]->path, &core_bfd, &core_num_syms,
                            &core_text_sect, &core_syms,
			    &core_min_insn_size, &core_offset_to_code))
	{
	if (reqlist != NULL)
	  free(reqlist);
	return(0);
	}
      object = md_set_object(md_objects[k]->path, options);
      /* search for unmatched symbols */
      md_init_extract_dynamic(core_num_syms, core_syms, 0);
      not_all_done = 0;
      for(i=0; i<nb_reqlist; i++)
        {
        if (reqlist[i].done == 0)
          {
	  /* Only check addresses that can reside in this module */
	  if (reqlist[i].loc->addr < md_objects[k]->base) {
	    not_all_done = 1;
	    continue;
	  }
	  /* Search for a valid name but missing object/file info */
	  if (reqlist[i].loc->valid)
	    {
	    int lo, hi, n;
            /* search if a symbol matches the given element */
	    for(lo=0, hi=md_nb_syms-1; lo<=hi;)
              {
	      j = (lo+hi)>>1;
	      n = strcmp(md_syms[j].name, reqlist[i].loc->name);
	      if (n==0)
	        break;
	      if (n>0)
	        hi = j-1;
	      else
	        lo = j+1;
	      }
	    if (n==0 &&
/*	        (md_syms[j].flag & (BSF_GLOBAL|BSF_WEAK))&& */
	  	(md_syms[j].flag & BSF_FUNCTION))
              {/* it's the same name AND it is a function that is exported! */
	      reqlist[i].loc->object = object;
	      reqlist[i].done = 1;
	      md_find_line(core_bfd, core_text_sect, core_syms,
	      		   (bfd_vma)reqlist[i].loc->addr, &reqlist[i], j, options);
	      }
	    else
	      not_all_done = 1;
	    }
	  else
	    not_all_done = 1;
          }
        }
      if (not_all_done)
        {
	/* Search for matching addresses, using the object base address */
        not_all_done = 0;
        qsort(md_syms, md_nb_syms, sizeof(MDSym), md_compare_pointers);
        for (i=0; i<md_nb_syms; i++) {
			long l = (long)md_syms[i].addr + (long)md_objects[k]->base;
			md_syms[i].addr = (void *)l;
		}
        for (i=0; i<nb_reqlist; i++)
          {
	    if (reqlist[i].loc->valid)
	      continue;
	    /* Only check addresses that can reside in this module */
	    if (reqlist[i].loc->addr < md_objects[k]->base)
	      {
	      not_all_done = 1;
	      continue;
	      }
		if (k && reqlist[i].loc->addr < md_objects[k-1]->base)
			reqlist[i].loc->object = object;
	    if (md_extract_dynamic(&reqlist[i], &j) &&
        	(md_syms[j].flag & (BSF_GLOBAL|BSF_LOCAL|BSF_WEAK)))
	      {
	      reqlist[i].done = 1;
	      md_find_line(core_bfd, core_text_sect, core_syms,
			            (bfd_vma)(reqlist[i].loc->addr - md_objects[k]->base),
				    &reqlist[i], j, options);
	      }
	    else
	      not_all_done = 1;
	  }
	}
      
      md_fini_extract_dynamic();
      /* close this bfd */
      bfd_close(core_bfd);
      free(core_syms);
      }
    }

  /* add a default name for all unknown symbols */
  for(i=0; i<nb_reqlist; i++)
    {
    if (reqlist[i].done == 0)
      {
      reqlist[i].loc->file = md_ndef_file;
	  if (!reqlist[i].loc->object)
        reqlist[i].loc->object = md_ndef_object;
      }
    else
      {
      if (!reqlist[i].xname->done)
        md_demangle(reqlist[i].xname, options);
      reqlist[i].loc->name = reqlist[i].xname->name;
      }
    }

  /* terminated */
  if (reqlist != NULL)
    free(reqlist);
  return(1);
}
