#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include"ft_list.h"


//change prev -> front & next -> back

void
ls_init(linked_list_t *ls) {//printf("ls init()\n");
        ls->head = NULL;
        ls->tail = NULL;
	ls->curr = NULL;
	ls->count = 0;
}

int
ls_empty(linked_list_t *ls) {
 	return ls->head == NULL;
}

void
ls_add(linked_list_t *ls, struct node *curr_node) {
//printf("ls_add()\n");
//the head stays the same, and the tail points to the last added node
//this holds for both following cases
//the next pointer points the node added after the current node
//printf("ls count is %d\n",ls->count);
	if(ls_empty(ls)) {//printf("ls is empty\n");
		ls->head = curr_node;
		ls->tail = curr_node;
		ls->curr = curr_node;
		curr_node->next = NULL;
		curr_node->prev = NULL;
	}	
	else {//printf("ls is not empty\n");
		curr_node->prev = ls->tail;
		curr_node->next = NULL;
		ls->tail->next = curr_node;
		ls->tail = curr_node;

//update:	no update of ls->curr in this case//?
	}

	ls->count++;
//printf("before leaving count is %d\n", ls->count);
}

void
ls_del(linked_list_t *ls, struct node *curr_node) {
//printf("ls_del()\n");
	if(ls_empty(ls)) return;

//print_nd_ptrs(curr_node);
//printf("ls count is %d\n",ls->count);
	if(curr_node == ls->head) {
		if(curr_node == ls->tail) { //printf("ls_del() 1\n");
			ls->curr = ls->tail = ls->head = NULL;
		}else { /*if(!ls->head->next) {
				printf("corrupted list head\n");
				print_nd_ptrs(ls->head);
				abort();
				}*/
			ls->head = ls->head->next;
			ls->head->prev = NULL;
		}
	}else
	if(curr_node == ls->tail) {
		ls->tail = ls->tail->prev;
		ls->tail->next = NULL;
	}else {
		curr_node->next->prev = curr_node->prev;
		curr_node->prev->next = curr_node->next;
	}

	if(ls->curr == curr_node)
		ls->curr = ls->curr->next;

	ls->count--;
}

struct node *
ls_fetch(linked_list_t *ls) {//printf("ls_fetch()\n");
	struct node * temp = ls->curr;
//print_nd_ptrs(ls->curr);
	if(ls->curr == NULL)
		ls->curr = ls->head;
	else
		ls->curr = ls->curr->next;
//print_nd_ptrs(ls->curr);
	return temp;
}

void //functionality included in ls_fetch()
ls_reset(linked_list_t *ls) {
	ls->curr = ls->head;
}

//CHECK should the return type be "void *" ??
struct node *
ls_search(linked_list_t *ls, void *key, int keysize) {
//printf("ls_search()\n");

//printf("ls: %p\t key: %d\t keysize: %d\n",ls,*((int *)key),keysize);
	struct node *curr_nd;

	if(ls_empty(ls)){//printf("list is empty\n");
		return NULL;}
	else{
		curr_nd = ls->head;
		while(curr_nd) {//printf("searching...\n");
//	printf("&current:%0p\n",curr_nd);
			if( memcmp(&curr_nd->key, key, keysize) == 0 )
				return curr_nd;
			curr_nd = curr_nd->next;
		}
		return NULL;
	}
}

/*
print_ls_ptrs(linked_list_t *ls) {
//printf("print_ls_ptrs start\n");
	printf("list's head ptr\n");
	print_nd_ptrs(ls->head);
	printf("list's tail ptr\n");
	print_nd_ptrs(ls->tail);
	printf("list's curr ptr\n");
	print_nd_ptrs(ls->curr);
	printf("ls count is %d\n",ls->count);
//printf("print_ls_ptrs end\n");
}
*/

ls_check(linked_list_t *ls) {

#define LS_VALID	0
#define LS_CORRUPT	1


	if(ls->count == 0) {
		if(ls->head != NULL
		|| ls->tail != NULL
		|| ls->curr != NULL)
			return LS_CORRUPT;
	}else
	if(ls->count == 1) {
		if(ls->head != ls->tail)
			return LS_CORRUPT;
	}else {
		if(ls->head->next == NULL
		|| ls->tail->prev == NULL)
			return LS_CORRUPT;
	}

	return LS_VALID;

}


/*
void
ls_free(linked_list_t *ls, struct node *nd) {
        if(ls_empty(ls)) return;
        if(nd == NULL) return;
        ls_del(ls,nd);
        free(nd);
}

int
Memcmp(char *s1, char *s2, int bcount) {
//printf("\n");
        char *tmp1 = s1;
        char *tmp2 = s2;

        while(bcount-- > 0) {//printf("\n");
                if(*tmp1++ == *tmp2++)
                        continue;
                else
                        return 1;
        }
        return 0;
}
*/

