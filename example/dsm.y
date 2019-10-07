%{
#  include <stdio.h>
#  include <stdlib.h>
#  include "dsm.h"
#  include "ndpi_protocol_ids.h"
// uncomment below to debug
//#define YYDEBUG 1
//yydebug = 1;
%}

%union {
  struct ast *a;
  double d;
  struct symbol *s;		/* which symbol */
  struct symlist *sl;
  struct parserlist *pl;
  int fn;			/* which function */
}

/* declare tokens */
%token <d> NUMBER
%token <s> NAME
%token <s> STRING
%token <fn> FUNC
%token EOL


%token IF THEN ELSE WHILE DO LET ENTER MATCH TRY_PARSER PER_PACKET


%left <fn> CON
%nonassoc <fn> CMP
%right '='
%left '+' '-'
%left '*' '/'
%nonassoc '|' UMINUS

%type <a> exp stmt list explist
%type <sl> symlist
%type <pl> parserlist

%start calclist

%%

stmt: IF exp THEN list           { $$ = newflow('I', $2, $4, NULL); }
   | IF exp THEN list ELSE list  { $$ = newflow('I', $2, $4, $6); }
   | WHILE exp DO list           { $$ = newflow('W', $2, $4, NULL); }
   | exp
;

list: /* nothing */ { $$ = NULL; }
   | stmt ';' list { if ($3 == NULL)
	                $$ = $1;
                      else
			$$ = newast('L', $1, $3);
                    }
   | '{' list '}'                { $$ = $2; }
   ;

exp: exp CMP exp          { $$ = newcmp($2, $1, $3); }
   | exp CON exp          { $$ = newcon($2, $1, $3); }
   | exp '+' exp          { $$ = newast('+', $1,$3); }
   | exp '-' exp          { $$ = newast('-', $1,$3);}
   | exp '*' exp          { $$ = newast('*', $1,$3); }
   | exp '/' exp          { $$ = newast('/', $1,$3); }
   | '|' exp              { $$ = newast('|', $2, NULL); }
   | '(' exp ')'          { $$ = $2; }
   | '-' exp %prec UMINUS { $$ = newast('M', $2, NULL); }
   | NUMBER               { $$ = newnum($1); }
   | FUNC '(' explist ')' { $$ = newfunc($1, $3); }
   | NAME                 { $$ = newref($1); }
   | NAME '=' exp         { $$ = newasgn($1, $3); }
   | NAME '(' explist ')' { $$ = newcall($1, $3); }
   | NAME '[' exp ']'     { $$ = newgetindex($1, $3);}
   | STRING         { $$ = newnum( (int) (*($1 ->name+1)) ); } /* add 1 to bypass ' */
   /*'\'' NAME '\''*/
;

explist: exp
 | exp ',' explist  { $$ = newast('L', $1, $3); }
;
symlist: NAME       { $$ = newsymlist($1, NULL); }
 | NAME ',' symlist { $$ = newsymlist($1, $3); }
;

parserlist: NAME       { $$ = newparserlist($1, NULL); }
| NAME ',' parserlist { $$ = newparserlist($1, $3); }
;

calclist: /* nothing */
  | calclist EOL   /* allow blank end lines*/
  | calclist stmt EOL {
    if(debug) dumpast($2, 0);
     printf("= %4.4g\n> ", eval($2, NULL));
     treefree($2);
    }
  | calclist LET NAME '(' symlist ')' '=' list EOL {
                       dodef($3, $5, $8);
                       printf("Defined %s\n> ", $3->name); }
  | calclist ENTER exp MATCH exp TRY_PARSER parserlist EOL {
      struct rawdsmrule *rule = newrawrule($3, $5, $7);
      addrawrule(rule);
    }
    | calclist ENTER exp PER_PACKET list MATCH exp TRY_PARSER parserlist EOL {
        struct rawdsmrule *rule = newrawrule_perpkt($3, $5,$7, $9);
        addrawrule(rule);
        //printf("here");
    }
  | calclist error EOL { yyerrok; printf("> "); }
 ;
%%
