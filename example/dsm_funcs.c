/* Companion source code for "flex & bison", published by O'Reilly
 * Media, ISBN 978-0-596-15597-1
 * Copyright (c) 2009, Taughannock Networks. All rights reserved.
 * See the README file for license conditions and contact info.
 * $Header: /home/johnl/flnb/code/RCS/fb3-2funcs.c,v 2.1 2009/11/08 02:53:18 johnl Exp $
 */
/*
 * helper functions for fb3-2
 */
#  include <stdio.h>
#  include <stdlib.h>
#  include <stdarg.h>
#  include <string.h>
#  include <math.h>
#  include <stddef.h>  // for offsetof
#  include "dsm.h"


struct rawdsmrule *tcprules[RULES_BUF];
struct symbol symtab[NHASH];

char *PROTOCOL_NAMES[] =
{
    "NDPI_PROTOCOL_FTP_CONTROL","NDPI_PROTOCOL_MAIL_POP","NDPI_PROTOCOL_HTTP","NDPI_PROTOCOL_BITTORRENT",
    "NDPI_PROTOCOL_UNENCRYPTED_JABBER","NDPI_PROTOCOL_RDP","NDPI_PROTOCOL_SSL", "NDPI_PROTOCOL_SSH", "NDPI_PROTOCOL_HTTP_ACTIVESYNC","NDPI_PROTOCOL_TEAMVIEWER",
    "ABORT_DETECION",
    "_END_"  // MUST be the last one
};

int PROTOCOL_VALUES[] =
{
    1,2,7,37,
    67,88,91,92,110,148,
    ABORT_DETECTION_PROTOCOL_ID
};

int convert_to_protocol_id(char *name)
{
    // Check wether we are using raw id number but no text
    if (strstr(name, "ID_") == name)
    {
        int id = atoi(name+3);
        if (id != 0)
        {
            return id;
        }
    }
    
    int i = 0;
    while(strncmp(PROTOCOL_NAMES[i], "_END_", 255) != 0)
    {
        if (strncmp(PROTOCOL_NAMES[i], name, 255) == 0) {
            return PROTOCOL_VALUES[i];
        }
        ++i;
    }
    
    return -1;
}

/* symbol table */
/* hash a symbol */
static unsigned
symhash(char *sym)
{
    unsigned int hash = 0;
    unsigned c;
    
    while(c = *sym++) hash = hash*9 ^ c;
    
    return hash;
}

struct symbol *
lookup(char* sym)
{
    struct symbol *sp = &symtab[symhash(sym)%NHASH];
    int scount = NHASH;        /* how many have we looked at */
    
    while(--scount >= 0) {
        if(sp->name && !strcmp(sp->name, sym)) { return sp; }
        
        if(!sp->name) {        /* new entry */
            sp->name = strdup(sym);
            sp->type = symtype_direct_double_val;
            sp->index = 0;
            sp->value = 0;
            sp->func = NULL;
            sp->syms = NULL;
            return sp;
        }
        
        if(++sp >= symtab+NHASH) sp = symtab; /* try the next entry */
    }
    yyerror("symbol table overflow\n");
    abort(); /* tried them all, table is full */
    
}



struct ast *
newast(int nodetype, struct ast *l, struct ast *r)
{
    struct ast *a = malloc(sizeof(struct ast));
    
    if(!a) {
        yyerror("out of space");
        exit(0);
    }
    a->nodetype = nodetype;
    a->l = l;
    a->r = r;
    return a;
}

struct ast *
newnum(double d)
{
    struct numval *a = malloc(sizeof(struct numval));
    
    if(!a) {
        yyerror("out of space");
        exit(0);
    }
    a->nodetype = 'K';
    a->number = d;
    return (struct ast *)a;
}

struct ast *
newcmp(int cmptype, struct ast *l, struct ast *r)
{
    struct ast *a = malloc(sizeof(struct ast));
    
    if(!a) {
        yyerror("out of space");
        exit(0);
    }
    a->nodetype = '0' + cmptype;
    a->l = l;
    a->r = r;
    return a;
}

struct ast *newcon(int cmptype, struct ast *l, struct ast *r)
{
    return newcmp(cmptype, l, r);
}

struct ast *
newfunc(int functype, struct ast *l)
{
    struct fncall *a = malloc(sizeof(struct fncall));
    
    if(!a) {
        yyerror("out of space");
        exit(0);
    }
    a->nodetype = 'F';
    a->l = l;
    a->functype = functype;
    return (struct ast *)a;
}

struct ast *
newcall(struct symbol *s, struct ast *l)
{
    struct ufncall *a = malloc(sizeof(struct ufncall));
    
    if(!a) {
        yyerror("out of space");
        exit(0);
    }
    a->nodetype = 'C';
    a->l = l;
    a->s = s;
    return (struct ast *)a;
}

struct ast *
newref(struct symbol *s)
{
    struct symref *a = malloc(sizeof(struct symref));
    
    if(!a) {
        yyerror("out of space");
        exit(0);
    }
    a->nodetype = 'N';
    a->s = s;
    return (struct ast *)a;
}

struct ast *
newasgn(struct symbol *s, struct ast *v)
{
    struct symasgn *a = malloc(sizeof(struct symasgn));
    
    if(!a) {
        yyerror("out of space");
        exit(0);
    }
    a->nodetype = '=';
    a->s = s;
    a->v = v;
    return (struct ast *)a;
}

struct ast *newgetindex(struct symbol *s, struct ast *i)
{
    struct symgetindex *a = malloc(sizeof(struct symgetindex));
    
    if(!a) {
        yyerror("out of space");
        exit(0);
    }
    a->nodetype = '[';
    a->s = s;
    a->i = i;
    return (struct ast *)a;
}

struct ast *
newflow(int nodetype, struct ast *cond, struct ast *tl, struct ast *el)
{
    struct flow *a = malloc(sizeof(struct flow));
    
    if(!a) {
        yyerror("out of space");
        exit(0);
    }
    a->nodetype = nodetype;
    a->cond = cond;
    a->tl = tl;
    a->el = el;
    return (struct ast *)a;
}

struct symlist *
newsymlist(struct symbol *sym, struct symlist *next)
{
    struct symlist *sl = malloc(sizeof(struct symlist));
    
    if(!sl) {
        yyerror("out of space");
        exit(0);
    }
    sl->sym = sym;
    sl->next = next;
    return sl;
}

void
symlistfree(struct symlist *sl)
{
    struct symlist *nsl;
    
    while(sl) {
        nsl = sl->next;
        free(sl);
        sl = nsl;
    }
}


struct parserlist *newparserlist(struct symbol* s, struct parserlist *next)
{
    struct parserlist *sl = malloc(sizeof(struct parserlist));
    memset(sl, 0, sizeof(struct parserlist));
    
    if(!sl) {
        yyerror("out of space");
        exit(0);
    }
    sl->name = strdup(s->name);
    sl->next = next;
    return sl;
}

void parserlistfree(struct parserlist *sl)
{
    struct parserlist *nsl;
    
    while(sl) {
        nsl = sl->next;
        free(sl->name);
        free(sl);
        sl = nsl;
    }
}

struct rawdsmrule *newrawrule(struct ast *enterexp, struct ast *matchexp,struct parserlist *parserlist)
{
    struct rawdsmrule *sl = malloc(sizeof(struct rawdsmrule));
    memset(sl, 0, sizeof(struct rawdsmrule));
    
    if(!sl) {
        yyerror("out of space");
        exit(0);
    }
    sl->enterexp = enterexp;
    sl->matchexp = matchexp;
    sl->parserlist = parserlist;
    return sl;
}

struct rawdsmrule *newrawrule_perpkt(struct ast *enterexp, struct ast *perpacket, struct ast *matchexp,struct parserlist *parserlist)
{
    struct rawdsmrule *sl = malloc(sizeof(struct rawdsmrule));
    memset(sl, 0, sizeof(struct rawdsmrule));
    
    if(!sl) {
        yyerror("out of space");
        exit(0);
    }
    sl->enterexp = enterexp;
    sl->perpacket = perpacket;
    sl->matchexp = matchexp;
    sl->parserlist = parserlist;
    return sl;
}

int is_existing(struct symbol *tosearch, struct symbol *array[], int blankindex)
{
    for (int i = 0; i < blankindex; ++i) {
        if( array[i] == tosearch)
        {
            return 1;
        }
    }
    return 0;
}

void check_symbol_to_add(struct symbol *s, struct symbol *array[], int *blankindex)
{
    if (s->type == symtype_direct_double_val)
    {
        if ( is_existing( s, array, *blankindex ) != 1 && *blankindex < MAX_CUSTOM_VALUE )
        {
            array[*blankindex] = s;
            *blankindex = *blankindex + 1;
        }
    }
}

void getsymbols(struct ast *a, struct symbol *array[], int *blankindex)
{
    if (a == NULL) {
        return;
    }
    
    switch(a->nodetype) {
            /* constant */
        case 'K': ; break;
            
            /* name reference */
        case 'N':
        {
            check_symbol_to_add(((struct symref *)a)->s, array, blankindex);
            break;
        }
            
            /* assignment */
        case '=':
            check_symbol_to_add(((struct symasgn *)a)->s, array, blankindex);
            getsymbols(((struct symasgn *)a)->v, array, blankindex);
            break;
        case '[':
            check_symbol_to_add(((struct symgetindex *)a)->s, array, blankindex);
            getsymbols(((struct symgetindex *)a)->i, array, blankindex);
            break;
            
            /* expressions */
        case '+':
        case '-':
        case '*':
        case '/':
        case '|':
        case 'M':
            
            /* comparisons */
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
            
        case 'L':
            getsymbols(a->l, array, blankindex);
            getsymbols(a->r, array, blankindex);
            break;
            
            /* control flow */
            /* null if/else/do expressions allowed in the grammar, so check for them */
        case 'I':
            getsymbols( ((struct flow *)a)->cond, array, blankindex);
            getsymbols( ((struct flow *)a)->tl, array, blankindex);
            getsymbols( ((struct flow *)a)->el, array, blankindex);
            break;
            
        case 'W':
            getsymbols(((struct flow *)a)->cond, array, blankindex);
            getsymbols(((struct flow *)a)->tl, array, blankindex);
            break;            /* last value is value */
            
            
        case 'F': break;
            
        case 'C': break;
            
        default: printf("internal error: getsymbols bad node %d\n", a->nodetype);
    }
}

void preprocess_rawrule(struct rawdsmrule *rule)
{
    // First, fill the index value of custom symbols.
    struct symbol *array[MAX_CUSTOM_VALUE];
    int current_index = 0;
    if(rule->perpacket != NULL)
    {
        getsymbols(rule->perpacket, array, &current_index);
        //printf("now current_index=%d \n", current_index);
        
        int current_offset = 0;
        for (int i = 0; i < current_index; ++i)
        {
            struct symbol *s = array[i];
            // Now assume newly defined variable is uint8 type.
            s->type = symtype_base_uint8_indexed;
            s->index = offsetof(struct dsm_flow_data, ext_data);
            current_offset += 1;
        }
    }
    
    //Second, fill the protoid based on protocol parser name
    struct parserlist * pl = rule->parserlist;
    while(pl != NULL)
    {
        int id =  convert_to_protocol_id(pl->name);
        if (id == -1) {
            printf("error:cannot find protocol name %s\n", pl->name);
        }else{
            pl->protoid = (uint16_t)id;
        }
        pl = pl->next;
    }
}

int tcprule_size = 0;

void addrawrule(struct rawdsmrule *rule)
{
    preprocess_rawrule(rule);
    
    tcprules[tcprule_size] = rule;
    ++tcprule_size;
    //printf("ttest = %s\n", PROTOCOL_NAMES[1]);
    //printf("offset = %d\n",offsetof(struct dsm_flow_data, server_port));
    dumprawrule(rule);
}

/* define a function */
void
dodef(struct symbol *name, struct symlist *syms, struct ast *func)
{
    if(name->syms) symlistfree(name->syms);
    if(name->func) treefree(name->func);
    name->syms = syms;
    name->func = func;
}

static double callbuiltin(struct fncall *, struct dsm_flow_data *);
static double calluser(struct ufncall *, struct dsm_flow_data *);

double
eval(struct ast *a, struct dsm_flow_data *data)
{
    double v;
    
    if(!a) {
        yyerror("internal error, null eval");
        return 0.0;
    }
    
    switch(a->nodetype) {
            /* constant */
        case 'K': v = ((struct numval *)a)->number; break;
            
            /* name reference */
        case 'N':
        {
            switch (((struct symref *)a)->s->type) {
                case symtype_direct_double_val:
                    v = ((struct symref *)a)->s->value;
                    break;
                case symtype_base_uint8_indexed:
                    v = *( (uint8_t*) ( (uint8_t*)data + ((struct symref *)a)->s->index));
                    break;
                case symtype_base_uint16_indexed:
                    v = *( (uint16_t*) ( (uint8_t*)data + ((struct symref *)a)->s->index));
                    break;
                default:
                    printf("error type here for 'N'.\n");
                    break;
            }
            break;
        }
            
            /* assignment */
        case '=':
        {
            v = ((struct symasgn *)a)->s->value =
            eval(((struct symasgn *)a)->v, data);
            
            switch (((struct symref *)a)->s->type) {
                case symtype_direct_double_val:
                    ((struct symasgn *)a)->s->value = v;
                    break;
                case symtype_base_uint8_indexed:
                    *( (uint8_t*) ( (uint8_t*)data + ((struct symref *)a)->s->index)) = round(v);
                    break;
                case symtype_base_uint16_indexed:
                    *( (uint16_t*) ( (uint8_t*)data + ((struct symref *)a)->s->index)) = round(v);
                    break;
                default:
                    printf("error type here for '='.\n");
                    break;
            }
            
            
            break;
        }
            
        case '[':
        {
            switch (((struct symgetindex *)a)->s->type) {
                case symtype_base_uint8pointer_indexed:
                {
                    int index = (int)eval( ((struct symgetindex *)a)->i, data);
                    uint8_t* temp = (uint8_t*) data + ((struct symgetindex *)a)->s->index; /*e.g.,get pointer to payload */
                    v = *( * ((uint8_t**)temp) + index );
                    break;
                }
                default:
                    printf("error type here for '['.\n");
                    break;
            }
            break;
        }
            
            /* expressions */
        case '+': v = eval(a->l, data) + eval(a->r, data); break;
        case '-': v = eval(a->l, data) - eval(a->r, data); break;
        case '*': v = eval(a->l, data) * eval(a->r, data); break;
        case '/': v = eval(a->l, data) / eval(a->r, data); break;
        case '|': v = fabs(eval(a->l, data)); break;
        case 'M': v = -eval(a->l, data); break;
            
            /* comparisons */
        case '1': v = (eval(a->l, data) > eval(a->r, data))? 1 : 0; break;
        case '2': v = (eval(a->l, data) < eval(a->r, data))? 1 : 0; break;
        case '3': v = (eval(a->l, data) != eval(a->r, data))? 1 : 0; break;
        case '4': v = (eval(a->l, data) == eval(a->r, data))? 1 : 0; break;
        case '5': v = (eval(a->l, data) >= eval(a->r, data))? 1 : 0; break;
        case '6': v = (eval(a->l, data) <= eval(a->r, data))? 1 : 0; break;
        case '7': // "&&"
        {
            v = eval(a->l, data) && eval(a->r, data);
            break;
        }
        case '8': // "||"
        {
            v = eval(a->l, data) || eval(a->r, data);
            break;
        }
            
            /* control flow */
            /* null if/else/do expressions allowed in the grammar, so check for them */
        case 'I':
            if( eval( ((struct flow *)a)->cond, data) != 0) {
                if( ((struct flow *)a)->tl) {
                    v = eval( ((struct flow *)a)->tl, data);
                } else
                    v = 0.0;        /* a default value */
            } else {
                if( ((struct flow *)a)->el) {
                    v = eval(((struct flow *)a)->el, data);
                } else
                    v = 0.0;        /* a default value */
            }
            break;
            
        case 'W':
            v = 0.0;        /* a default value */
            
            if( ((struct flow *)a)->tl) {
                while( eval(((struct flow *)a)->cond, data) != 0)
                    v = eval(((struct flow *)a)->tl, data);
            }
            break;            /* last value is value */
            
        case 'L': eval(a->l, data); v = eval(a->r, data); break;
            
        case 'F': v = callbuiltin((struct fncall *)a, data); break;
            
        case 'C': v = calluser((struct ufncall *)a, data); break;
            
        default: printf("internal error: bad node %c\n", a->nodetype);
    }
    return v;
}

static double
callbuiltin(struct fncall *f, struct dsm_flow_data *data)
{
    enum bifs functype = f->functype;
    double v = eval(f->l, data);
    
    switch(functype) {
        case B_sqrt:
            return sqrt(v);
        case B_exp:
            return exp(v);
        case B_log:
            return log(v);
        case B_print:
            printf("= %4.4g\n", v);
            return v;
        default:
            yyerror("Unknown built-in function %d", functype);
            return 0.0;
    }
}

static double
calluser(struct ufncall *f, struct dsm_flow_data *data)
{
    struct symbol *fn = f->s;    /* function name */
    struct symlist *sl;        /* dummy arguments */
    struct ast *args = f->l;    /* actual arguments */
    double *oldval, *newval;    /* saved arg values */
    double v;
    int nargs;
    int i;
    
    if(!fn->func) {
        yyerror("call to undefined function", fn->name);
        return 0;
    }
    
    /* count the arguments */
    sl = fn->syms;
    for(nargs = 0; sl; sl = sl->next)
        nargs++;
    
    /* prepare to save them */
    oldval = (double *)malloc(nargs * sizeof(double));
    newval = (double *)malloc(nargs * sizeof(double));
    if(!oldval || !newval) {
        yyerror("Out of space in %s", fn->name); return 0.0;
    }
    
    /* evaluate the arguments */
    for(i = 0; i < nargs; i++) {
        if(!args) {
            yyerror("too few args in call to %s", fn->name);
            free(oldval); free(newval);
            return 0;
        }
        
        if(args->nodetype == 'L') {    /* if this is a list node */
            newval[i] = eval(args->l, data);
            args = args->r;
        } else {            /* if it's the end of the list */
            newval[i] = eval(args, data);
            args = NULL;
        }
    }
    
    /* save old values of dummies, assign new ones */
    sl = fn->syms;
    for(i = 0; i < nargs; i++) {
        struct symbol *s = sl->sym;
        
        oldval[i] = s->value;
        s->value = newval[i];
        sl = sl->next;
    }
    
    free(newval);
    
    /* evaluate the function */
    v = eval(fn->func, data);
    
    /* put the dummies back */
    sl = fn->syms;
    for(i = 0; i < nargs; i++) {
        struct symbol *s = sl->sym;
        
        s->value = oldval[i];
        sl = sl->next;
    }
    
    free(oldval);
    return v;
}


void
treefree(struct ast *a)
{
    switch(a->nodetype) {
            
            /* two subtrees */
        case '+':
        case '-':
        case '*':
        case '/':
        case '1':  case '2':  case '3':  case '4':  case '5':  case '6': case '7': case '8':
        case 'L':
            treefree(a->r);
            
            /* one subtree */
        case '|':
        case 'M': case 'C': case 'F':
            treefree(a->l);
            
            /* no subtree */
        case 'K': case 'N':
            break;
            
        case '=':
            free( ((struct symasgn *)a)->v);
            break;
            /* get index */
        case '[':
            free( ((struct symgetindex *)a)->i);
            break;
            
        case 'I': case 'W':
            free( ((struct flow *)a)->cond);
            if( ((struct flow *)a)->tl) free( ((struct flow *)a)->tl);
            if( ((struct flow *)a)->el) free( ((struct flow *)a)->el);
            break;
            
        default: printf("internal error: free bad node %c\n", a->nodetype);
    }
    
    free(a); /* always free the node itself */
    
}

void
yyerror(char *s, ...)
{
    va_list ap;
    va_start(ap, s);
    
    fprintf(stderr, "%d: error: ", yylineno);
    vfprintf(stderr, s, ap);
    fprintf(stderr, "\n");
}

void testrules()
{
    struct dsm_flow_data data;
    memset(&data, 0, sizeof(struct dsm_flow_data));
    char payload[200];
    data.protocol = 6;
    data.server_port = 21;
    data.pkt_num = 6;
    data.payload_pkt_num = 4;
    data.payload_len = 20;
    data.payload = (uint8_t*)&payload;
    payload[0] = 'P';
    payload[1] = 'A';
    
    printf("rule0 enterexp eval result %f\n",eval(tcprules[0]->enterexp, &data));
    printf("rule0 matchexp eval result %f\n",eval(tcprules[0]->matchexp, &data));
    
    memset(&data, 0, sizeof(struct dsm_flow_data));
    data.protocol = 6;
    data.server_port = 443;
    data.pkt_num = 1;
    data.payload_pkt_num = 2;
    data.payload_len = 200;
    data.payload = (uint8_t*)&payload;
    payload[0] = 20;
    
    printf("rule2 enterexp eval result %f\n",eval(tcprules[2]->enterexp, &data));
    printf("rule2 perpacket eval result %f\n",eval(tcprules[2]->perpacket, &data));
    printf("rule2 matchexp eval result %f\n",eval(tcprules[2]->matchexp, &data));
}

/*
int
main(int argc, char **argv)
{
    
    if(argc > 1) {
        extern FILE*  yyin;
        if(!(yyin = fopen(argv[1], "r"))) {
            perror(argv[1]);
            return (1);
        }
    }
    
    printf("> ");
    int ret = yyparse();
    
    testrules();
    
    return 0;
}
 */

/* debugging: dump out an AST */
int debug = 0;
void
dumpast(struct ast *a, int level)
{
    
    printf("%*s", 2*level, "");    /* indent to this level */
    level++;
    
    if(!a) {
        printf("NULL\n");
        return;
    }
    
    switch(a->nodetype) {
            /* constant */
        case 'K': printf("number %4.4g\n", ((struct numval *)a)->number); break;
            
            /* name reference */
        case 'N': printf("ref %s (%d,%d)\n", ((struct symref *)a)->s->name, ((struct symref *)a)->s->type,
                         ((struct symref *)a)->s->index ); break;
            
            /* assignment */
        case '=': printf("= %s\n", ((struct symref *)a)->s->name);
            dumpast( ((struct symasgn *)a)->v, level); return;
            
            /* get index */
        case '[': printf(" %s (%d,%d) [\n", ((struct symref *)a)->s->name, ((struct symref *)a)->s->type,
                         ((struct symref *)a)->s->index );
            dumpast( ((struct symgetindex *)a)->i, level);
            printf("     ]\n");return;
            
            /* expressions */
        case '+': case '-': case '*': case '/': case 'L':
        case '1': case '2': case '3':
        case '4': case '5': case '6':
        case '7':case '8':
            printf("binop %c\n", a->nodetype);
            dumpast(a->l, level);
            dumpast(a->r, level);
            return;
            
        case '|': case 'M':
            printf("unop %c\n", a->nodetype);
            dumpast(a->l, level);
            return;
            
        case 'I': case 'W':
            printf("flow %c\n", a->nodetype);
            dumpast( ((struct flow *)a)->cond, level);
            if( ((struct flow *)a)->tl)
                dumpast( ((struct flow *)a)->tl, level);
            if( ((struct flow *)a)->el)
                dumpast( ((struct flow *)a)->el, level);
            return;
            
        case 'F':
            printf("builtin %d\n", ((struct fncall *)a)->functype);
            dumpast(a->l, level);
            return;
            
        case 'C': printf("call %s\n", ((struct ufncall *)a)->s->name);
            dumpast(a->l, level);
            return;
            
        default: printf("bad %c\n", a->nodetype);
            return;
    }
}

void dumprawrule(struct rawdsmrule *rule)
{
    printf("enter exp:\n");
    dumpast(rule->enterexp,0);
    if(rule->perpacket != NULL){
        printf("per_packet:\n");
        dumpast(rule->perpacket,0);
    }
    printf("match exp:\n");
    dumpast(rule->matchexp,0);
    dumpparserlist(rule->parserlist);
}

void dumpparserlist(struct parserlist * pl)
{
    while(pl != NULL)
    {
        printf("parser: %s (%d) ", pl->name, pl->protoid);
        pl = pl->next;
    }
    printf("\n");
    
}
