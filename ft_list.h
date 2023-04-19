#ifndef	__FT_LIST_H
#define __FT_LIST_H

#define MAX_ND_KLEN 76

struct node{
        struct node *prev;
        struct node *next;
	char key[MAX_ND_KLEN];
//	char data[1];
};

typedef struct linked_list_s{
        struct node *head;
        struct node *tail;
	struct node *curr; //current node to fetch
	unsigned int count;
}linked_list_t;

void ls_init(linked_list_t *);

int ls_empty(linked_list_t *);

void ls_add(linked_list_t *, struct node *);

void ls_del(linked_list_t *, struct node *);

struct node *ls_fetch(linked_list_t *);

void ls_reset(linked_list_t *);

struct node *ls_search(linked_list_t *, void *, int);

void ls_free(linked_list_t *, struct node *);


#endif //__FT_LIST_H
