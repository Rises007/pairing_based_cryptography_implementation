/* Contributed by Rajdeep Mistri
 */
/* Here we represent the original A provable secure identity based 2paka iiot enviroments
 * This protocol has 3 stages: Setup and Private key generation and setup session key. We represent them inside one code block with demo and time outputs.
 */

/*
SETUP:
1.	PKG chooses G1, G2, e: G1*G1 -> GT, P, H: {0, 1}* -> G1, s, H - some function for key calculation.
2.	PKG calculates P0 = s*P(master private key), publishes {G1, GT e, P, P0, H1, H} and saves 's' as master public key.

PRIVATE KEY GENERATION:
1.	Pi submits his identity to PKG (ID1,ID2)
2. 	PKG calculates :
	private key Pri = {s/(s + qi)}*P, where qi = H1(ID1)

SESSION KEY GENERATION:
1.	P1 chooses r1 ∈ Zq∗ at random, and calculates ψ1 = r1 ·P
	and σ1 = r1 ·Pr1 . Now, P1 sends {ψ1 , σ1 } to P2 over a
	public channel.
	
2.	P2 selects r2 ∈ Zq∗ at random, and calculates ψ2 = r2·P
	and σ2 = r2 ·Pr2 Now, P2 sends {ψ 2 , σ 2 } to P 1 over a public channel.

3.	After receiving {ψ2 , σ2 } from P2 , P1 verifies whether the 
	condition ê(σ2 , P0 + q2·P ) = ê(ψ2 , P0) holds, where
	q2 = H1(ID2 ). If the verification is successful, then P1
	computes the session key as sk1 = H2(ID1 || ID2 || ψ1 ||
	ψ2 || X), where X = r1 · ψ2

4.	After receiving {ψ1 , σ1 } from P1 , P2 verifies whether the
	condition ê(σ1 , P0 + q1·P) = ê(ψ1 , P0) holds, where
	q1 = H1 (ID1). If the verification is successful, then P 2
	computes the session key as sk2 = H2 (ID1 || ID2 || ψ1 ||
	ψ2 || X), where X = r2 · ψ1	


\u03A8 = Psi symbol
\u03C3 = Sigma symbol
*/

#include <pbc/pbc.h>
#include <pbc/pbc_test.h>

#include <string.h>

int main(int argc, char **argv) {
  pairing_t pairing;
  double t0, t1;
  element_t s, r1, r2, P, P0, Q1, Q2, Pr1, Pr2, sig1, sig2, Sai1, Sai2,Sai3, Sai4, Kab, Kba, K, temp1,
    temp2, temp3, temp4, temp5, tmp1, tmp2, tmp3, tmp4, lhs, rhs, X, y;
  element_t hash1, hash2;

  pbc_demo_pairing_init(pairing, argc, argv);
  if (!pairing_is_symmetric(pairing)) pbc_die("pairing must be symmetric");

  element_init_Zr(s, pairing);
  element_init_Zr(r1, pairing);
  element_init_Zr(r2, pairing);
  element_init_G1(Q1, pairing);
  element_init_G1(Q2, pairing);
  
  element_init_G1(Sai1, pairing);
  element_init_G1(Sai2, pairing);
  element_init_G1(Sai3, pairing);
  element_init_G1(Sai4, pairing);

  element_init_G1(sig1, pairing);
  element_init_G1(sig2, pairing);
  
  element_init_G1(P, pairing);
  element_init_G1(P0, pairing);
 
  element_init_G1(Pr1, pairing);
  element_init_G1(Pr2, pairing);
 
  element_init_G1(temp1, pairing);
  element_init_G1(temp2, pairing);
  element_init_G1(temp3, pairing);
  element_init_G1(temp4, pairing);
  element_init_G1(temp5, pairing);
  element_init_G1(tmp1, pairing);
  element_init_G1(tmp2, pairing);
  element_init_G1(tmp3, pairing);
  element_init_G1(tmp4, pairing);

  element_init_G1(X, pairing);
  
  
  element_init_G1(y, pairing);
 
  
  element_init_G1(hash1, pairing);
  element_init_G1(hash2, pairing);

  element_init_GT(Kab, pairing);
  element_init_GT(Kba, pairing);
  element_init_GT(K, pairing);
  element_init_GT(lhs, pairing);
  element_init_GT(rhs, pairing);
  printf("\n2PAKA key agreement protocol \n\n");

  t0 = pbc_get_time();

//Setup, system parameters generation
  printf("---SETUP STAGE---\n\n");
  element_random(P);
  element_printf("P = %B\n\n", P);
  element_random(s);
  element_mul_zn(P0, P, s);
  element_printf("P0 = %B\n\n", P0);

//Extract, key calculation
  printf("---EXTRACT STAGE---\n");
  element_from_hash(Q1, "A", 1);
  element_from_hash(Q2, "B", 1);
  printf("Hash on IDs done\n\n");
 
  
 //Pri added
  element_mul_zn(tmp1, s, P);
  element_add(tmp2, s, Q1);
  element_div(Pr1, tmp1, tmp2);
  
  element_mul_zn(temp1, s, P);
  element_add(temp2, s, Q2);
  element_div(Pr2, temp1, temp2); 
  //
  
 //element_mul_zn(Sa, Q1, s);
 //element_mul_zn(Sb, Q2, s);
  element_printf("Pr1 = %B\n\n", Pr1);
  element_printf("Pr2 = %B\n\n", Pr2);	
  
  printf("-----1-----\n\n");

  element_random(r1);
  element_mul_zn(Sai1, P, r1);
  element_printf("A sends B \u03A81 = %B\n\n", Sai1);
  
  element_mul_zn(sig1, Pr1, r1);
  element_printf("A sends B \u03C31 = %B\n\n", sig1);
  
  printf("-----2-----\n\n");

  element_random(r2);
  element_mul_zn(Sai2, P, r2);
  element_printf("B sends A \u03A82 = %B\n\n", Sai2);
	
  element_mul_zn(sig2, Pr2, r2);
  element_printf("B sends A \u03C32 = %B\n\n", sig2);
  
  printf("-----2.5-----\n\n");
  
  printf(" e'(\u03C32, P0 + Q2.P) == e'(\u03A82, P0) \n");
  //We check condition e^(sig2, P0 + Q2.P) == e^(Sai2, P0)
  element_mul_zn(tmp3, Q2, P);
  element_add(tmp4, P0, tmp3);
  
  pairing_pp_t pp1, pp2;
  pairing_pp_init(pp1, tmp4, pairing);
  pairing_pp_init(pp2, P0, pairing);
  
  pairing_pp_apply(lhs, sig2, pp1);
  pairing_pp_apply(rhs, Sai2, pp2);
  
  
  //element_pairing(lhs, sig2, tmp4);
  
  //element_pairing(rhs, Sai2, P0);
   
  element_printf("A lhs = %B\n\n", lhs);
  element_printf("A rhs = %B\n", rhs);
  printf("\ncmp value = %d i.e.,",element_cmp(lhs,rhs));
  if(!element_cmp(lhs,rhs))
  	printf(" Equal \n");
  else
  	printf(" Not Equal \n");
  printf("-----3-----\n\n");
  
  
 
  printf("A calculates X and sk1\n");
  element_mul_zn(X, Sai2, r1);
  element_printf("X = %B\n", X);

  
  //sk = "A" || "B" || Sai1 || Sai2 || X;
  printf("\nsk = H(ID1 || ID2 || \u03A81 || \u03A82 || X)\n");
  
  
  //done by rajdeep
  
 /* element_set_str(Sai1, "uihuhihoioi",16);
  element_set_str(Sai2, "yufyuguihu",16);
  element_set_str(X, "yugyguu",16);*/
 // element_printf("Sai1 = %B\n", Sai1);
  
  
  // Determine the required buffer size for the string representation
  size_t str1_size = element_length_in_bytes(Sai1); // Multiply by 2 to accommodate hexadecimal representation
  size_t str2_size = element_length_in_bytes(Sai2) ;
  size_t str3_size = element_length_in_bytes(X) ;
  
  // Allocate memory for the string representation
  char* str1 = (char*)malloc(str1_size * sizeof(char));
  char* str2 = (char*)malloc(str2_size * sizeof(char));
  char* str3 = (char*)malloc(str3_size * sizeof(char));
  
  // Convert the element to its string representation
  element_snprintf(str1, str1_size, "%B", Sai1);
  element_snprintf(str2, str2_size, "%B", Sai2);
  element_snprintf(str3, str3_size, "%B", X); 
  
  //initializing str
  size_t total = str1_size + str2_size + str3_size + 1;
  char* str = (char*)malloc( total* sizeof(char));
  strcpy(str,"A");
  		
  strcat(str,"B");
  strcat(str,str1);  
  strcat(str,str2);
  strcat(str,str3);
  
  element_from_hash(hash1, str, sizeof(str));
  
  element_printf("sk1: %B\n\n",hash1);
  //
  
  printf("Now B calculates X and sk2\n");
  element_mul_zn(X, Sai1, r2);
  element_printf("X = %B\n\n", X);
  
  element_set(Sai3, Sai1);
  element_set(Sai4, Sai2);

	//********  Must be done again in B's system  *********
  /*element_set_str(Sai3, "element in string format",16);
  element_set_str(Sai4, "element in string format",16);
  element_set_str(X, "element in string format",16);*/
   
  
  //element_printf("Sai1 = %B\n", Sai3);
  
  
  // Determine the required buffer size for the string representation
  size_t str4_size = element_length_in_bytes(Sai3)  ; // Multiply by 2 to accommodate hexadecimal representation
  size_t str5_size = element_length_in_bytes(Sai4)  ;
  size_t str6_size = element_length_in_bytes(X)  ;
  
  // Allocate memory for the string representation
  char* str4 = (char*)malloc(str4_size * sizeof(char));
  char* str5 = (char*)malloc(str5_size * sizeof(char));
  char* str6 = (char*)malloc(str6_size * sizeof(char));
  
  // Convert the element to its string representation
  element_snprintf(str4, str4_size, "%B", Sai3);
  element_snprintf(str5, str5_size, "%B", Sai4);
  element_snprintf(str6, str6_size, "%B", X); 
  
  //initializing str
  size_t total2 = str4_size + str5_size + str6_size + 1;
  char* str0 = (char*)malloc( total2* sizeof(char));
  strcpy(str0,"A");
  		
  strcat(str0,"B");
  strcat(str0,str4);  
  strcat(str0,str5);
  strcat(str0,str6);
  
  //char l1[10] = "sdfdsf";
  
  element_from_hash(hash2, str0, sizeof(str0));
  
  element_printf("sk2: %B\n\n",hash2);

  if (!element_cmp(hash1, hash2))
    printf("The keys are the same. Start session...\n");
  else
    printf("The keys aren't the same. Try again, please.\n");
    
  element_clear(K);
  element_clear(Kab);
  element_clear(Kba);
  element_clear(X);
  element_clear(temp1);
  element_clear(temp2);
  element_clear(temp3);
  element_clear(temp4);
  element_clear(temp5);
  element_clear(tmp1);
  element_clear(tmp2);
  element_clear(s);
  element_clear(r1);
  element_clear(r2);
  element_clear(P);
  element_clear(P0);
  element_clear(Q1);
  element_clear(Q2);
  element_clear(Pr1);
  element_clear(Pr2);
  element_clear(Sai1);
  element_clear(Sai2);

  t1 = pbc_get_time();

  printf("All time = %fs\n", t1 - t0);
  printf("Have a good day!\n");

  return 0;
}
