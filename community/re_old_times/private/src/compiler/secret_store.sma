#include <amxmodx>
#include <nvault>

// #pragma compress 1 // anti amxxdump

new g_nvault;
new account_menu;

public plugin_init(){
	register_plugin("Secret store", "21.37", "RiviT");

	register_clcmd("say /menu", "cmd_menu");
	register_clcmd("say /login", "cmd_menu");
	register_clcmd("say /register", "cmd_menu");
	register_clcmd("radio1", "cmd_menu");
	// register_clcmd("say /gen", "generate_entries");

	register_clcmd("secret", "handle_secret_input");
	register_cvar("secret_random_value", "11");

	g_nvault = nvault_open("store");

	create_menu();
}

stock create_menu(){
	account_menu = menu_create("Account system", "menu_handle");
	menu_additem(account_menu, "Store secret");
	menu_additem(account_menu, "View secret");
}

public plugin_end(){
	nvault_close(g_nvault);
}

public cmd_menu(id){
	return menu_display(id, account_menu);
}

public cmd_view_secret(id){
	new vault_data[512];
	new was_found = nvault_get(g_nvault, fmt("%n", id), vault_data, charsmax(vault_data));
	if(was_found){
		client_print(id, 3, "Your encoded secret is: %s", vault_data);
	}else{
		client_print(id, 3, "Your store is empty");
	}

	return 1;
}

public cmd_store_secret(id){
	client_cmd(id, "messagemode secret");
	return 1;
}

public menu_handle(id, menu, item){
	if(item == MENU_EXIT || !is_user_connected(id)){
		return 0;
	}
	return item == 0 ? cmd_store_secret(id) : cmd_view_secret(id);
}

public encode_secret(id, secret[], secret_len){
	new name[33];
	new nick_len = get_user_name(id, name, charsmax(name));

	for(new i = 0, j = 0; i < secret_len; i++){
		secret[i] ^= name[j++];
		j %= nick_len;
	}

	for(new i = 0; i+1 < secret_len; i += 2){
		new t = secret[i];
		secret[i] = secret[i+1];
		secret[i+1] = t;
	}

	new xor_coeff = get_cvar_num("secret_random_value");
	for(new i = 0; i < secret_len; i++){
		new c = secret[i];
		new a = ((c & 0xF) ^ xor_coeff) << 4;
		new b = (((c & 0xF0) >> 4) ^ (~xor_coeff & 0xF));
		secret[i] = a | b;
	}
}

public handle_secret_input(id){
	new secret[192];
	new secret_len = read_argv(1, secret, charsmax(secret));

	encode_secret(id, secret, secret_len);

	new bytes[512];
	bytes_to_str(secret, secret_len, bytes, charsmax(bytes));

	new name[33];
	get_user_name(id, name, charsmax(name));
	nvault_set(g_nvault, name, bytes);
	client_print(id, 3, "Your secret was stored in the vault");
	return 1;
}

public bytes_to_str(encoded[], encoded_len, bytes[], bytes_len){
	for(new i = 0; i < encoded_len; i++){
		add(bytes, bytes_len, fmt("%02x", encoded[i]));
	}
}

// public generate_entries(id){
// 	enum kLoginData {
// 		GEN_LOGIN[32],
// 		GEN_PASSWD[128]
// 	}
// 	new kLoginData:nicks[][kLoginData] = {
// 		{"Rivit", "6487b4058215e01151"},
// 		{"Pwner", "45f6d5c4279150f46504c1f6e044c694502585d495f6142426b4"},
// 		{"Smurf", "9467b515e5"},
// 		{"Player", "3785e5c685b49496551590e187f7e5a166a47187c5f5a091879650f180c5410775"},
// 		{"Defuser", "d5a72584d5d5f2a48484c4f5b4b5a6"},
// 		{"Samurai", "24f6a474349183152534"},
// 		{"Sniper", "6597d564a4f434c78434f5a4"},
// 		{"Deadeye", "6487b5b435e0f234a076b5c5e524d506b4f464e0f214e5d5c504e075b476a48511"},
// 	}

// 	for(new i = 0; i < sizeof(nicks); i++){
// 		nvault_set(g_nvault, fmt("%s", nicks[i][GEN_LOGIN]), fmt("%s", nicks[i][GEN_PASSWD]));
// 	}
// }
