/* $OpenLDAP: pkg/ldap/include/avl.h,v 1.19 2001/05/29 01:29:57 kurt Exp $ */
/*
 * Copyright 1998-2001 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.  A copy of this license is available at
 * http://www.OpenLDAP.org/license.html or in file LICENSE in the
 * top-level directory of the distribution.
 */
/* Portions
 * Copyright (c) 1993 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */
/* avl.h - avl tree definitions */


#ifndef _AVL
#define _AVL

/*
 * this structure represents a generic avl tree node.
 */

typedef struct avlnode Avlnode;

struct avlnode {
	void*		avl_data;
	signed int		avl_bf;
	struct avlnode	*avl_left;
	struct avlnode	*avl_right;
};

#define NULLAVL	((Avlnode *) NULL)

/* balance factor values */
#define LH 	(-1)
#define EH 	0
#define RH 	1

/* avl routines */
#define avl_getone(x)	((x) == 0 ? 0 : (x)->avl_data)
#define avl_onenode(x)	((x) == 0 || ((x)->avl_left == 0 && (x)->avl_right == 0))

typedef int		(*AVL_APPLY) (void *, void*);
typedef int		(*AVL_CMP) (const void*, const void*);
typedef int		(*AVL_DUP) (void*, void*);
typedef void	(*AVL_FREE) (void*);

int
avl_free ( Avlnode *root, AVL_FREE dfree );

int
avl_insert (Avlnode **, void*, AVL_CMP, AVL_DUP);

void*
avl_delete (Avlnode **, void*, AVL_CMP);

Avlnode*
avl_find (Avlnode *, const void*, AVL_CMP);

void*
avl_find_lin (Avlnode *, const void*, AVL_CMP);

#ifdef AVL_NONREENTRANT
void*
avl_getfirst (Avlnode *);

void*
avl_getnext (void);
#endif

int
avl_dup_error (void*, void*);

int
avl_dup_ok (void*, void*);

int
avl_apply (Avlnode *, AVL_APPLY, void*, int, int);

int
avl_prefixapply (Avlnode *, void*, AVL_CMP, void*, AVL_CMP, void*, int);

/* apply traversal types */
#define AVL_PREORDER	1
#define AVL_INORDER	2
#define AVL_POSTORDER	3
/* what apply returns if it ran out of nodes */
#define AVL_NOMORE	(-6)

#endif /* _AVL */
