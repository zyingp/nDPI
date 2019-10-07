/* Companion source code for "flex & bison", published by O'Reilly
 * Media, ISBN 978-0-596-15597-1
 * Copyright (c) 2009, Taughannock Networks. All rights reserved.
 * See the README file for license conditions and contact info.
 * $Header: /home/johnl/flnb/code/RCS/fb3-2.h,v 2.1 2009/11/08 02:53:18 johnl Exp $
 */
/*
 * Declarations for a calculator fb3-1
 */


#ifndef _DSM_H
#define _DSM_H

#include <stdint.h>

#define MAX_CUSTOM_VALUE 8
#define ABORT_DETECTION_PROTOCOL_ID  65535

#define RULES_BUF 20
struct rawdsmrule;
extern struct rawdsmrule *tcprules[RULES_BUF];
extern int tcprule_size;   // current size

#pragma pack(1)
struct dsm_flow_data
{
    uint8_t   protocol;
    uint16_t  server_port;
    uint8_t   pkt_num;
    uint8_t   payload_pkt_num;
    uint16_t  payload_len;
    uint8_t  *payload;
    uint8_t   ext_data[MAX_CUSTOM_VALUE];
};

enum symtype
{
    symtype_direct_double_val,
    symtype_base_uint8_indexed, // a uint8 value, whose index is offset to the base flow pointer
    symtype_base_uint16_indexed,// a uint16 value, whose index is offset to the base flow pointer
    symtype_base_uint8pointer_indexed
};

/* symbol table */
struct symbol {		/* a variable name */
  char *name;
  enum symtype type;
  double value;
  int    index;
  struct ast *func;	/* stmt for the function */
  struct symlist *syms; /* list of dummy args */
};

/* simple symtab of fixed size */
#define NHASH 9997
extern struct symbol symtab[NHASH];

struct symbol *lookup(char*);

/* list of symbols, for an argument list */
struct symlist {
  struct symbol *sym;
  struct symlist *next;
};

/* list of parsers, for an parser list */
struct parserlist {
    char *name;
    uint16_t protoid;        // filled later based on name
    struct parserlist *next;
};

struct symlist *newsymlist(struct symbol *sym, struct symlist *next);
void symlistfree(struct symlist *sl);

struct parserlist *newparserlist(struct symbol* s, struct parserlist *next);
void parserlistfree(struct parserlist *sl);

/* node types
 *  + - * / |
 *  0-7 comparison ops, bit coded 04 equal, 02 less, 01 greater
 *  M unary minus
 *  L statement list
 *  I IF statement
 *  W WHILE statement
 *  N symbol ref
 *  = assignment
 *  S list of symbols
 *  F built in function call
 *  C user function call
 */ 

enum bifs {			/* built-in functions */
  B_sqrt = 1,
  B_exp,
  B_log,
  B_print
};

/* nodes in the Abstract Syntax Tree */
/* all have common initial nodetype */

struct ast {
  int nodetype;
  struct ast *l;
  struct ast *r;
};

struct fncall {			/* built-in function */
  int nodetype;			/* type F */
  struct ast *l;
  enum bifs functype;
};

struct ufncall {		/* user function */
  int nodetype;			/* type C */
  struct ast *l;		/* list of arguments */
  struct symbol *s;
};

struct flow {
  int nodetype;			/* type I or W */
  struct ast *cond;		/* condition */
  struct ast *tl;		/* then or do list */
  struct ast *el;		/* optional else list */
};

struct numval {
  int nodetype;			/* type K */
  double number;
};

struct symref {
  int nodetype;			/* type N */
  struct symbol *s;
};

struct symasgn {
  int nodetype;			/* type = */
  struct symbol *s;
  struct ast *v;		/* value */
};

struct symgetindex {
    int nodetype;            /* type [ */
    struct symbol *s;
    struct ast *i;        /* index */
};

/* raw dsm rule, one cooresponding to one line in rules.txt*/
struct rawdsmrule
{
    struct ast *enterexp;
    struct ast *perpacket;
    struct ast *matchexp;
    struct parserlist *parserlist;
};

/* build an AST */
struct ast *newast(int nodetype, struct ast *l, struct ast *r);
struct ast *newcmp(int cmptype, struct ast *l, struct ast *r);
struct ast *newcon(int cmptype, struct ast *l, struct ast *r);
struct ast *newfunc(int functype, struct ast *l);
struct ast *newcall(struct symbol *s, struct ast *l);
struct ast *newref(struct symbol *s);
struct ast *newasgn(struct symbol *s, struct ast *v);
struct ast *newnum(double d);
struct ast *newflow(int nodetype, struct ast *cond, struct ast *tl, struct ast *tr);

struct ast *newgetindex(struct symbol *s, struct ast *v);


struct rawdsmrule *newrawrule(struct ast *enterexp, struct ast *matchexp,struct parserlist *parserlist);
struct rawdsmrule *newrawrule_perpkt(struct ast *enterexp, struct ast *perpacket, struct ast *matchexp,struct parserlist *parserlist);

/* define a function */
void dodef(struct symbol *name, struct symlist *syms, struct ast *stmts);

/* evaluate an AST */
double eval(struct ast *, struct dsm_flow_data *data);

/* delete and free an AST */
void treefree(struct ast *);



void addrawrule(struct rawdsmrule *rule);


/* interface to the lexer */
extern int yylineno; /* from lexer */
void yyerror(char *s, ...);

extern int debug;
void dumpast(struct ast *a, int level);
void dumprawrule(struct rawdsmrule *rule);
void dumpparserlist(struct parserlist * pl);

int yyparse (); // for used in ndpi

#endif
