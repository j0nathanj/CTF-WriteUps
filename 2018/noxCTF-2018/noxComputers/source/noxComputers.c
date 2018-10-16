#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

/*----------------------------------*/
/*       Some definitions           */
/*----------------------------------*/

#define ARRAY_MAX              1024   // MAX ARRAY LENGTH
#define PADDING_MAX            1024   // MAX PADDING SIZE
#define MAX_NAME_SIZE          32     // MAX NAME LENGTH
#define MAX_SHORT              65536  // == 2^16 (this is actually MAX_SHORT + 1)
#define DISCOUNT_MAGIC         3
#define SERIAL_MAGIC           3133731337
#define MIN_MONEY_FOR_NORMAL   5
#define MIN_MONEY_FOR_ELIGIBLE 10

/*----------------------------------*/
/*       Structs definitions        */
/*----------------------------------*/

typedef struct computer{
	char* name;
	char* manufacturer;
	unsigned short price;
	unsigned int serial_number;
	unsigned short owners;
	unsigned int isSuperFast;
} computer;

typedef struct user{
	char* name;
	struct computer_node* computers;
	unsigned short computer_count;
	unsigned int id_number;
	unsigned short money;
	unsigned int eligible_for_discount;
} user;

typedef struct computer_node{
	struct computer* computer;
	struct computer_node* next;
	struct computer_node* prev;
} computer_node;

/*----------------------------------*/
/*        Function declarations     */
/*----------------------------------*/
void buy_premium_user();
void buy_multiple_premium_users();
void buy_computer();
void show_account_details();
void edit_account_details();
void return_computer();

computer_node* unlink_computer(computer_node* comp_node);
computer_node* find_computer(computer_node* computers_list, char* comp_name);
computer_node* traverse_to_head(computer_node* somewhere_in_the_list);

/*----------------------------------*/
/*        Global variables          */
/*----------------------------------*/

unsigned short user_count = 0;
unsigned short computer_count = 0;
user* users[ARRAY_MAX] = {0}; 
unsigned char padding1[PADDING_MAX] = {0};
computer* computers_array[ARRAY_MAX] = {0};
unsigned char padding2[MAX_SHORT * sizeof(void*)] = {0};
unsigned char computers_bitmap[ARRAY_MAX] = {0};
unsigned int discount_rate = 0;

/*----------------------------------------------*/
/*      Functions Actual Implementations        */
/*----------------------------------------------*/

void puts_wrapper(char* str)
{
	puts(str);
	fflush(stdout);
}

void padding_fake(){
	
	for(unsigned int i = 0; i < MAX_SHORT; i++)
	{
		padding1[i] = '\0';
	}

	for(unsigned int i = 0; i < MAX_SHORT * sizeof(void*); i++)
	{
		padding2[i] = '\0';
	}
}

void printf_wrapper(char* str)
{
	printf(str);
	fflush(stdout);
}

void generate_discount_rate()
{
	srand(time(NULL));
	discount_rate = rand() % 71;
}

void insert_computer(user* a_user, computer* a_computer)
{
	computer_node* new_node = (computer_node*) malloc(sizeof(struct computer_node));
	new_node->computer = a_computer;
	computer_node* curr = a_user->computers;
	computer_node* curr_prev = NULL;

	if(a_user->computers == NULL)
	{
		new_node->prev = NULL;
		new_node->next = NULL;
		a_user->computers = new_node;
	}
	else
	{
		for(unsigned short i = 0; i < a_user->computer_count; i++){
			curr_prev = curr;
			curr = curr->next;
		}

		if(curr_prev->next != NULL)
		{
			puts_wrapper("Error - Incompatibility Detected!");
			exit(0);
		}

		curr_prev->next = (computer_node*) new_node;
		new_node->prev = (computer_node*) curr_prev;
		new_node->next = (computer_node*) NULL;	
	}
	
}

void print_computers(user* a_user)
{
	unsigned int i = 0;
	computer_node* curr = NULL;

	if(a_user->computers == NULL)
	{
		printf_wrapper("You don't own any computers\n");
		return;
	}

	curr = a_user->computers;
	while(curr != NULL)
	{
		printf("* ---- Details of your #%d computer ---- *\n", i);
		printf("- Computer name of your #%d computer: %s\n", i, ((curr->computer)->name));
		fflush(stdout);
		printf("- Manufacturer name of your #%d computer is: %s\n", i, (curr->computer)->manufacturer);
		fflush(stdout);
		printf("- The price of your #%d computer is: %hu\n", i, (curr->computer)->price);
		fflush(stdout);
		printf("- The Serial Number of your #%d computer is: %u\n", i, (curr->computer)->serial_number);
		fflush(stdout);
		
		if((curr->computer)->isSuperFast)
		{
			printf("- Your #%d computer is SUPER FAST\n", i);
			fflush(stdout);
		}
		else
		{
			printf("- Your #%d computer is NOT SUPER FAST\n", i);
			fflush(stdout);
		}
		puts_wrapper("");

		i++;
		curr = curr->next;
	}
}

void banner()
{
	puts_wrapper("");
	puts_wrapper("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
	puts_wrapper("***************************************************************************");
	puts_wrapper("                      Welcome to noxComputers Ltd.                         ");
	puts_wrapper("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
	puts_wrapper("***************************************************************************");
	puts_wrapper("");
	puts_wrapper("[$] We sell the BEST computers in the world!");
	puts_wrapper("");
	puts_wrapper("[+] We have a lot of cool policies for the benefit of our customers!");
	puts_wrapper("    Make sure you enjoy them, because they are made for you!");
	fflush(stdout);
}


void print_menu()
{
	puts("");
	puts_wrapper("What would you like to do?");
	puts_wrapper("1. Buy a premium user membership");
	puts_wrapper("2. Buy multiple premium memberships AND BE ELIGIBLE FOR UP TO 70% DISCOUNT!");
	puts_wrapper("3. Buy a computer");
	puts_wrapper("4. Show account details");
	puts_wrapper("5. Edit account details");
	puts_wrapper("6. Return a computer");
	puts_wrapper("7. Exit");
	printf_wrapper("Your choice: ");
	fflush(stdout);
}

void custom_read(char* dest, unsigned int length)
{	
	char current = '\0';
	int bytes_read = 0;
	for(;bytes_read < length;)
	{
		read(0, &current, 1);
		if(bytes_read == length-1 && current != '\n' && current != '\0')
		{
			*(dest + bytes_read) = '\0';
			break;
		}
		else if(current != '\n')
		{
			*(dest + bytes_read) = current;
			bytes_read++;
		}
		else
		{
			*(dest + bytes_read) = '\0';
			break;
		}
		
	}	
}

void buy_premium_user()
{
	unsigned short the_money = 0;
	user* new_user = NULL;
	char* new_username = NULL;

	if(user_count >= ARRAY_MAX)
	{
		puts_wrapper("Maximum users created!");
		return;
	}

	new_username = (char*) malloc(MAX_NAME_SIZE);
	new_user = (user*) malloc(sizeof(struct user));

	printf_wrapper("Enter your username: ");
	custom_read(new_username, MAX_NAME_SIZE);

	printf_wrapper("Enter the amount of money to add to your account: ");
	scanf("%hu", &the_money);

	if(the_money < MIN_MONEY_FOR_NORMAL)
	{
		puts_wrapper("We give you a gift of 5$ to use in our shop!\n");
		the_money = MIN_MONEY_FOR_NORMAL;
	}
	
	new_user->name = new_username;
	new_user->id_number = user_count;
	new_user->money = the_money;
	new_user->computers = NULL;
	new_user->computer_count = 0;
	new_user->eligible_for_discount = 0;

	users[user_count] = new_user;
	user_count++;
}

void buy_multiple_premium_users()
{
	unsigned short premiums_amount = 0;
	user* new_user = NULL;
	char* new_name = NULL;
	unsigned short the_money = 0;
	unsigned char done = 0;

	printf_wrapper("Enter the amount of premiums you would like to buy: ");
	scanf("%hu", &premiums_amount);

	if((unsigned short)(user_count + premiums_amount) > ARRAY_MAX) 
	{
		puts_wrapper("You can't create more than 1024 users :(");
		return;
	}

	puts_wrapper("As a prize for creating multiple premiums, you are eligible for future discounts!");

	for(unsigned short i = 0; i < premiums_amount; i++)
	{
		
		new_user = (user*) malloc(sizeof(struct user));	
		new_name = (char*) malloc(MAX_NAME_SIZE);

		printf_wrapper("If you'd like to stop creating more accounts, press Y: ");
		read(0, &done, 1);
		if(done != '\n')
		{
			getchar();
		}

		if(done == 'Y')
		{
			puts_wrapper("Thank you and have a good day!");
			break;
		}

		printf("Enter the username of user #%d: ", i);
		fflush(stdout);
		custom_read(new_name, MAX_NAME_SIZE);
		new_user->name = new_name;

		printf("Enter the amount of money to add to the #%d user: ", i);
		fflush(stdout);
		scanf("%hu", &the_money);

		new_user->money = the_money;
		new_user->id_number = user_count;
		new_user->computers = NULL;
		new_user->computer_count = 0;
		new_user->eligible_for_discount = 1;
		users[user_count] = new_user;
		user_count++;
		
		if(new_user->money < MIN_MONEY_FOR_ELIGIBLE)
		{
			new_user->money = MIN_MONEY_FOR_ELIGIBLE;
			puts_wrapper("We gave you a gift of 10$ to use in our shop!");
		}

		printf("Successfully created the #%d member!\n", i);
		fflush(stdout);
	}
}

void buy_computer()
{
	unsigned int user_id = 0;
	computer* a_computer = NULL;
	char* computer_name = NULL;
	char* manufacturer_name = NULL;
	unsigned char does_exist = 0;
	unsigned char super_fast = 0;
	unsigned short price = 0;
	unsigned int serial = 0;
	unsigned char would_buy = 0;
	unsigned short discount_factor = 0;
	unsigned short is_discounted = 0;

	printf_wrapper("Enter your user id: ");
	scanf("%u", &user_id);

	if(user_id >= user_count || user_id >= ARRAY_MAX)
	{
		puts_wrapper("User ID is out of bounds!");
		return;
	}

	computer_name = (char*) malloc(MAX_NAME_SIZE);
	printf_wrapper("Enter computer name: ");
	custom_read(computer_name, MAX_NAME_SIZE);

	for(unsigned int i = 0; i < computer_count && !does_exist; i++)
	{
		if(computers_bitmap[i] && !strncmp(computer_name, computers_array[i]->name, MAX_NAME_SIZE))
		{
			if(computers_array[i]->owners < MAX_SHORT - 1)
			{
				free(computer_name);
				computer_name = computers_array[i]->name;
				does_exist = 1;
				a_computer = computers_array[i];
			}
			else
			{
				puts("This computer is Out of Stock right now :(");
				return;
			}
		}
	}

	if(!does_exist)
	{
		if(computer_count < ARRAY_MAX - 1)
		{
			a_computer = (struct computer*)malloc(sizeof(struct computer));
			a_computer->name = computer_name;

			printf_wrapper("Enter manufacturer name: ");
			manufacturer_name = (char*)malloc(MAX_NAME_SIZE);
			custom_read(manufacturer_name, MAX_NAME_SIZE);
			a_computer->manufacturer = manufacturer_name;

			printf_wrapper("Is this a SUPER fast computer?(Y/N): ");
			read(0, &super_fast, 1);

			if(super_fast != '\n')
			{
				getchar();
			}
			
			while(super_fast !='Y' && super_fast != 'N')
			{	
				puts_wrapper("Incorrect option!");
				printf_wrapper("Is this a SUPER fast computer?(Y/N): ");
				read(0, &super_fast, 1);

				if(super_fast != '\n')
				{
					getchar();
				}
			}
			
			if(super_fast == 'Y' )
			{
				a_computer->isSuperFast = 1;
			}
			else
			{
				a_computer->isSuperFast = 0;
			}	
			
			puts_wrapper("");
			puts_wrapper("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$");
			puts_wrapper("");
			puts_wrapper("We have a special policy, since we think our customers are the most important part of our business!");
			puts_wrapper("If you are the first customer to engage with this computer, we let YOU decide the price for the computer! :)");
			puts_wrapper("");
			puts_wrapper("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$");
			puts_wrapper("");

			printf_wrapper("Enter the amount of money you are willing to pay: ");
			scanf("%hu", &price);
			a_computer->price = price;

			serial = rand() % SERIAL_MAGIC;
			printf("The generated serial number is: %u\n", serial);
			fflush(stdout);
			a_computer->serial_number = serial;
			
			a_computer->owners = 0;
			computers_array[computer_count] = a_computer;
			computers_bitmap[computer_count++] = 1;
		}
		else
		{
			puts_wrapper("We can't order any more NEW computers :(");
			return;
		}
	}

	printf_wrapper("Would you like to buy this computer? (Y/N): ");
	read(0, &would_buy, 1);

	if(would_buy != '\n')
	{
		getchar();
	}

	while(would_buy !='Y' && would_buy != 'N')
	{	
		puts_wrapper("Incorrect option!");
		printf_wrapper("Would you like to buy this computer? (Y/N): ");
		read(0, &would_buy, 1);

		if(would_buy != '\n')
		{
			getchar();
		}
	}

	if(would_buy == 'Y')
	{
		price = a_computer->price;
		is_discounted = rand() % 10;

		if(is_discounted == DISCOUNT_MAGIC && users[user_id]->eligible_for_discount)
		{
			discount_factor = 100 - discount_rate;
			price = price - (discount_factor/100);
			printf("This item has %hu%% discount :)\n", discount_factor);
			fflush(stdout);
		}

		if(users[user_id]->money < price)
		{
			puts_wrapper("You don't have enough money!");
			return;
		}
		else
		{
			users[user_id]->money -= price;
			a_computer->owners++;
			insert_computer(users[user_id], a_computer);
			users[user_id]->computer_count++;
		}
	}

}

void show_account_details()
{
	unsigned int id_number = 0;
	printf_wrapper("Enter user id: ");
	scanf("%u", &id_number);

	if(id_number < user_count)
	{
		printf("Username: %s\n", users[id_number]->name);
		fflush(stdout);

		printf("Amount of money: %d\n", users[id_number]->money);
		fflush(stdout);

		if(users[id_number]->eligible_for_discount)
		{
			puts("Eligible for discount: YES!");
		}
		else
		{
			puts("Eligible for discount: No.. :(");
		}

		if(users[id_number]->computer_count)
		{
			printf("You have %hu computers from our store!\n", (users[id_number]->computer_count+1));
			fflush(stdout);
		}

		puts_wrapper("Details about your computers:");
		print_computers((struct user*) users[id_number]);
	}
	else
	{
		puts_wrapper("Index out of bounds!");
		return;
	}

}

void edit_account_details()
{
	unsigned int id_number = 0;
	char* username = NULL;
	unsigned short new_money = 0;
	printf_wrapper("Enter user id: ");
	scanf("%u", &id_number);

	if(id_number < user_count)
	{
		printf_wrapper("Enter new username: ");
		if(users[id_number] == NULL)
		{
			username = (char*) malloc(MAX_NAME_SIZE);	
		}
		else
		{
			username = users[id_number]->name;
		}
		
		custom_read(username, MAX_NAME_SIZE);

		printf_wrapper("Enter the new amount of money to add to your account: ");
		scanf("%hu", &new_money);

		users[id_number]->money = new_money;
		users[id_number]->name = username;
	}
	else
	{
		puts_wrapper("Index out of bounds!");
		return;
	}
}

void return_computer()
{
	unsigned int id_number = 0;
	char* computer_name = NULL;
	computer_node* curr_computer_node = NULL;
	computer* curr_computer = NULL;
	computer_node* temp = NULL;
	unsigned char found = 0;
	unsigned short owners = 0;
	char* name_holder = NULL;

	printf_wrapper("Enter user id: ");
	scanf("%u", &id_number);

	if(id_number < user_count)
	{

		computer_name = (char*) malloc(MAX_NAME_SIZE);
		printf_wrapper("Enter computer name: ");
		custom_read(computer_name, MAX_NAME_SIZE);

		for(unsigned short i = 0; i < computer_count; i++)
		{
			if(computers_bitmap[i] && !strncmp(computers_array[i]->name, computer_name, MAX_NAME_SIZE))
			{
				if(computers_array[i]->owners > 0)
				{
					computers_array[i]->owners--;
				}

				curr_computer_node = find_computer(users[id_number]->computers, computer_name);
				users[id_number]->money += curr_computer_node->computer->price;
				users[id_number]->computers = unlink_computer(curr_computer_node);
				users[id_number]->computer_count--;
				found = 1;
			}

			owners = computers_array[i]->owners;

			if(computers_bitmap[i] && 0 == owners)
			{
				name_holder = computers_array[i]->name;
				free((void*)(computers_array[i]->manufacturer));
				free((void*)(computers_array[i]));
				free(name_holder);
				computers_bitmap[i] = 0;
			}
		}

	}
	else
	{
		puts_wrapper("Index out of bounds!");
		return;
	}

	if(found)
	{
		puts_wrapper("You got your money back, we hope to see you here again soon!");
	}
	else
	{
		printf("You DON'T HAVE a computer named: %s \n", computer_name);
		fflush(stdout);
	}

}


computer_node* find_computer(computer_node* computers_list, char* comp_name)
{
    computer_node* curr_node = computers_list;
    computer_node* result = NULL;

    while(curr_node != NULL)
    {
        if(!strncmp(comp_name, curr_node->computer->name, MAX_NAME_SIZE))
        {
            result = curr_node;
            break;
        }

        curr_node = curr_node->next;
    }
    
    return result;
}


computer_node* unlink_computer(computer_node* comp_node)
{
	computer_node* temp = NULL;
	computer_node* to_free = comp_node;
	computer_node* result = NULL;

	if(comp_node->prev == NULL )
	{
		if(comp_node->next != NULL)
		{
			result = comp_node->next;
			comp_node->next->prev = NULL;
		}
		else
		{
			result = NULL;	
		}		
	}
	else if(comp_node->next == NULL)
	{
		result = comp_node->prev;
		comp_node->prev->next = NULL;
	}
	else
	{
		temp = comp_node->next;
		comp_node->prev->next = temp;
		temp->prev = comp_node->prev;
		result = comp_node->prev;
	}
	free(to_free);

	return traverse_to_head(result);
}

computer_node* traverse_to_head(computer_node* somewhere_in_the_list)
{
	computer_node* curr = somewhere_in_the_list;
	computer_node* head = NULL;

	while(curr != NULL)
	{
		if(curr->prev == NULL)
		{
			head = curr;
			break;
		}

		curr = curr->prev;
	}

	return head;
}


void menu()
{
	unsigned int choice = 0;	
	generate_discount_rate();

	while (choice != 7)
	{
		print_menu();
		scanf("%u", &choice);
		switch(choice)
		{
			case 1:
				buy_premium_user();
				break;
			case 2: 
				buy_multiple_premium_users();
				break;
			case 3:
				buy_computer();
				break;
			case 4:
				show_account_details();
				break;
			case 5:
				edit_account_details();
				break;
			case 6:
				return_computer();
				break;
			case 7:
				puts_wrapper("Was a pleasure working with you, Good bye!");
				exit(0);
			default:
				puts_wrapper("Invalid choice!");
				break;
		}
	}

}

int main(int argc, char *argv[], char *envp[])
{
	banner();
	menu();

	return 0;
}
