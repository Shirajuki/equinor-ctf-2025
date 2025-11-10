room_0(){  int result;   char v1;   pthread_mutex_lock(&DOORS);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    return pthread_mutex_unlock(&mutex);  return result;}
room_1(){  int result;   char v1;   pthread_mutex_lock(&stru_1D448);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_1D470);  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_1D830);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_1D510);  return result;}
room_2(){  pthread_mutex_lock(&stru_1D470);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_3(){  int result;   char v1;   pthread_mutex_lock(&stru_1D498);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_1D4C0);  return result;}
room_4(){  pthread_mutex_lock(&stru_1D4C0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_5(){  int result;   char v1;   pthread_mutex_lock(&stru_1D4E8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_1D5B0);  return result;}
room_6(){  int result;   char v1;   pthread_mutex_lock(&stru_1D510);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_1D8F8);  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_1E898);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_1D5D8);  return result;}
room_7(){  pthread_mutex_lock(&stru_1D538);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_8(){  int result;   char v1;   pthread_mutex_lock(&stru_1D560);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_1E8E8);  return result;}
room_9(){  int result;   char v1;   pthread_mutex_lock(&stru_1D588);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_1D560);  return result;}
room_10(){  pthread_mutex_lock(&stru_1D5B0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_11(){  int result;   char v1;   pthread_mutex_lock(&stru_1D5D8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_1E960);  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_1D600);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_1D6A0);  return result;}
room_12(){  pthread_mutex_lock(&stru_1D600);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_13(){  pthread_mutex_lock(&stru_1D628);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_14(){  pthread_mutex_lock(&stru_1D650);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_15(){  pthread_mutex_lock(&stru_1D678);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_16(){  int result;   char v1;   pthread_mutex_lock(&stru_1D6A0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_1D678);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_1D768);  return result;}
room_17(){  int result;   char v1;   pthread_mutex_lock(&stru_1D6C8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_1DAB0);  return result;}
room_18(){  pthread_mutex_lock(&stru_1D6F0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_19(){  int result;   char v1;   pthread_mutex_lock(&stru_1D718);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_1EAA0);  return result;}
room_20(){  int result;   char v1;   pthread_mutex_lock(&stru_1D740);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_1DB28);  return result;}
room_21(){  int result;   char v1;   pthread_mutex_lock(&stru_1D768);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_1D790);  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_1DB50);  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_1EAF0);  return result;}
room_22(){  pthread_mutex_lock(&stru_1D790);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_23(){  int result;   char v1;   pthread_mutex_lock(&stru_1D7B8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_1D6F0);  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_1D7E0);  return result;}
room_24(){  int result;   char v1;   pthread_mutex_lock(&stru_1D7E0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_1D718);  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_1DBC8);  return result;}
room_25(){  pthread_mutex_lock(&stru_1D808);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_26(){  pthread_mutex_lock(&stru_1D830);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_27(){  int result;   char v1;   pthread_mutex_lock(&stru_1D858);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_1D920);  return result;}
room_28(){  int result;   char v1;   pthread_mutex_lock(&stru_1D880);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_1D858);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_1D498);  return result;}
room_29(){  pthread_mutex_lock(&stru_1D8A8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_30(){  int result;   char v1;   pthread_mutex_lock(&stru_1D8D0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_1D4E8);  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_1D808);  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_1DCB8);  return result;}
room_31(){  pthread_mutex_lock(&stru_1D8F8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_32(){  int result;   char v1;   pthread_mutex_lock(&stru_1D920);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_1D538);  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_1ECA8);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_1D9E8);  return result;}
room_33(){  pthread_mutex_lock(&stru_1D948);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_34(){  int result;   char v1;   pthread_mutex_lock(&stru_1D970);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_1D948);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_1D588);  return result;}
room_35(){  int result;   char v1;   pthread_mutex_lock(&stru_1D998);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_1ED20);  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_1D8D0);  return result;}
room_36(){  pthread_mutex_lock(&stru_1D9C0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_37(){  int result;   char v1;   pthread_mutex_lock(&stru_1D9E8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_1DA10);  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_1D9C0);  return result;}
room_38(){  int result;   char v1;   pthread_mutex_lock(&stru_1DA10);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_1DA38);  return result;}
room_39(){  pthread_mutex_lock(&stru_1DA38);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_40(){  pthread_mutex_lock(&stru_1DA60);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_41(){  int result;   char v1;   pthread_mutex_lock(&stru_1DA88);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_1DA60);  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_1EE10);  return result;}
room_42(){  int result;   char v1;   pthread_mutex_lock(&stru_1DAB0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_1DE98);  return result;}
room_43(){  pthread_mutex_lock(&stru_1DAD8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_44(){  pthread_mutex_lock(&stru_1DB00);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_45(){  int result;   char v1;   pthread_mutex_lock(&stru_1DB28);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_1DF10);  return result;}
room_46(){  pthread_mutex_lock(&stru_1DB50);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_47(){  pthread_mutex_lock(&stru_1DB78);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_48(){  int result;   char v1;   pthread_mutex_lock(&stru_1DBA0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_1DB78);  return result;}
room_49(){  int result;   char v1;   pthread_mutex_lock(&stru_1DBC8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_1EF50);  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_1DFB0);  return result;}
room_50(){  pthread_mutex_lock(&stru_1DBF0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_51(){  pthread_mutex_lock(&stru_1DC18);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_52(){  int result;   char v1;   pthread_mutex_lock(&stru_1DC40);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_1DC68);  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_1EFC8);  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_1E028);  return result;}
room_53(){  pthread_mutex_lock(&stru_1DC68);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_54(){  int result;   char v1;   pthread_mutex_lock(&stru_1DC90);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_1E078);  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_1D8A8);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_1DD58);  return result;}
room_55(){  int result;   char v1;   pthread_mutex_lock(&stru_1DCB8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_1DBF0);  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_1E0A0);  return result;}
room_56(){  int result;   char v1;   pthread_mutex_lock(&stru_1DCE0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_1DC18);  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_1DDA8);  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_1E0C8);  return result;}
room_57(){  int result;   char v1;   pthread_mutex_lock(&stru_1DD08);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_1DC40);  return result;}
room_58(){  int result;   char v1;   pthread_mutex_lock(&stru_1DD30);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_1DD08);  return result;}
room_59(){  int result;   char v1;   pthread_mutex_lock(&stru_1DD58);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_1DD30);  return result;}
room_60(){  int result;   char v1;   pthread_mutex_lock(&stru_1DD80);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_1E168);  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_1DE48);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_1D998);  return result;}
room_61(){  pthread_mutex_lock(&stru_1DDA8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_62(){  pthread_mutex_lock(&stru_1DDD0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_63(){  pthread_mutex_lock(&stru_1DDF8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_64(){  pthread_mutex_lock(&stru_1DE20);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_65(){  pthread_mutex_lock(&stru_1DE48);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_66(){  int result;   char v1;   pthread_mutex_lock(&stru_1DE70);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_1F1F8);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_1DA88);  return result;}
room_67(){  int result;   char v1;   pthread_mutex_lock(&stru_1DE98);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_1F220);  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_1DDD0);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_1DF60);  return result;}
room_68(){  int result;   char v1;   pthread_mutex_lock(&stru_1DEC0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_1DDF8);  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_1DAD8);  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_1E2A8);  return result;}
room_69(){  int result;   char v1;   pthread_mutex_lock(&stru_1DEE8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_1DB00);  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_1DEC0);  return result;}
room_70(){  int result;   char v1;   pthread_mutex_lock(&stru_1DF10);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_1E2F8);  return result;}
room_71(){  int result;   char v1;   pthread_mutex_lock(&stru_1DF38);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_1F2C0);  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_1DE70);  return result;}
room_72(){  int result;   char v1;   pthread_mutex_lock(&stru_1DF60);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_1DF38);  return result;}
room_73(){  pthread_mutex_lock(&stru_1DF88);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_74(){  pthread_mutex_lock(&stru_1DFB0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_75(){  int result;   char v1;   pthread_mutex_lock(&stru_1DFD8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_1E3C0);  return result;}
room_76(){  pthread_mutex_lock(&stru_1E000);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_77(){  int result;   char v1;   pthread_mutex_lock(&stru_1E028);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_1E0F0);  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_1E050);  return result;}
room_78(){  int result;   char v1;   pthread_mutex_lock(&stru_1E050);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_1E438);  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_1F3D8);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_1E118);  return result;}
room_79(){  pthread_mutex_lock(&stru_1E078);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_80(){  int result;   char v1;   pthread_mutex_lock(&stru_1E0A0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_1F428);  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_1E488);  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_1DFD8);  return result;}
room_81(){  int result;   char v1;   pthread_mutex_lock(&stru_1E0C8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_1E000);  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_1F450);  return result;}
room_82(){  int result;   char v1;   pthread_mutex_lock(&stru_1E0F0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_1F478);  return result;}
room_83(){  int result;   char v1;   pthread_mutex_lock(&stru_1E118);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_1E140);  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_1E1E0);  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_1E500);  return result;}
room_84(){  pthread_mutex_lock(&stru_1E140);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_85(){  pthread_mutex_lock(&stru_1E168);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_86(){  int result;   char v1;   pthread_mutex_lock(&stru_1E190);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_1E1B8);  return result;}
room_87(){  pthread_mutex_lock(&stru_1E1B8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_88(){  pthread_mutex_lock(&stru_1E1E0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_89(){  int result;   char v1;   pthread_mutex_lock(&stru_1E208);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_1E2D0);  return result;}
room_90(){  pthread_mutex_lock(&stru_1E230);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_91(){  pthread_mutex_lock(&stru_1E258);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_92(){  pthread_mutex_lock(&stru_1E280);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_93(){  int result;   char v1;   pthread_mutex_lock(&stru_1E2A8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_1E370);  return result;}
room_94(){  int result;   char v1;   pthread_mutex_lock(&stru_1E2D0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_1E398);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_1DEE8);  return result;}
room_95(){  int result;   char v1;   pthread_mutex_lock(&stru_1E2F8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_1E230);  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_1E320);  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_1E6E0);  return result;}
room_96(){  pthread_mutex_lock(&stru_1E320);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_97(){  pthread_mutex_lock(&stru_1E348);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_98(){  int result;   char v1;   pthread_mutex_lock(&stru_1E370);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_1E348);  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_1DF88);  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_1F6F8);  return result;}
room_99(){  pthread_mutex_lock(&stru_1E398);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_100(){  int result;   char v1;   pthread_mutex_lock(&stru_1E3C0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_1E3E8);  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_1F748);  return result;}
room_101(){  pthread_mutex_lock(&stru_1E3E8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_102(){  pthread_mutex_lock(&stru_1E410);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_103(){  pthread_mutex_lock(&stru_1E438);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_104(){  int result;   char v1;   pthread_mutex_lock(&stru_1E460);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_1E528);  return result;}
room_105(){  pthread_mutex_lock(&stru_1E488);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_106(){  pthread_mutex_lock(&stru_1E4B0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_107(){  pthread_mutex_lock(&stru_1E4D8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_108(){  int result;   char v1;   pthread_mutex_lock(&stru_1E500);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_1E4D8);  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_1F888);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_1E5C8);  return result;}
room_109(){  pthread_mutex_lock(&stru_1E528);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_110(){  pthread_mutex_lock(&stru_1E550);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_111(){  int result;   char v1;   pthread_mutex_lock(&stru_1E578);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_1E190);  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_1E4B0);  return result;}
room_112(){  int result;   char v1;   pthread_mutex_lock(&stru_1E5A0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_1E578);  return result;}
room_113(){  int result;   char v1;   pthread_mutex_lock(&stru_1E5C8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_1E5A0);  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_1E690);  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_1E5F0);  return result;}
room_114(){  int result;   char v1;   pthread_mutex_lock(&stru_1E5F0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_1E6B8);  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_1F978);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_1E208);  return result;}
room_115(){  int result;   char v1;   pthread_mutex_lock(&stru_1E618);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_1E550);  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_1F9A0);  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_1E640);  return result;}
room_116(){  int result;   char v1;   pthread_mutex_lock(&stru_1E640);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_1E668);  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_1F9C8);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_1E708);  return result;}
room_117(){  pthread_mutex_lock(&stru_1E668);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_118(){  pthread_mutex_lock(&stru_1E690);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_119(){  pthread_mutex_lock(&stru_1E6B8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_120(){  int result;   char v1;   pthread_mutex_lock(&stru_1E6E0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_1E618);  return result;}
room_121(){  int result;   char v1;   pthread_mutex_lock(&stru_1E708);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_1FA90);  return result;}
room_122(){  pthread_mutex_lock(&stru_1E730);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_123(){  int result;   char v1;   pthread_mutex_lock(&stru_1E758);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_1E730);  return result;}
room_124(){  pthread_mutex_lock(&stru_1E780);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_125(){  int result;   char v1;   pthread_mutex_lock(&mutex);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_1EB90);  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_1FB30);  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_1E7D0);  return result;}
room_126(){  int result;   char v1;   pthread_mutex_lock(&stru_1E7D0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_1D448);  return result;}
room_127(){  pthread_mutex_lock(&stru_1E7F8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_128(){  pthread_mutex_lock(&stru_1E820);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_129(){  pthread_mutex_lock(&stru_1E848);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_130(){  pthread_mutex_lock(&stru_1E870);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_131(){  pthread_mutex_lock(&stru_1E898);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_132(){  pthread_mutex_lock(&stru_1E8C0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_133(){  int result;   char v1;   pthread_mutex_lock(&stru_1E8E8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_1E820);  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_1E910);  return result;}
room_134(){  int result;   char v1;   pthread_mutex_lock(&stru_1E910);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_1E848);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_1E9D8);  return result;}
room_135(){  pthread_mutex_lock(&stru_1E938);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_136(){  pthread_mutex_lock(&stru_1E960);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_137(){  int result;   char v1;   pthread_mutex_lock(&stru_1E988);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_1E8C0);  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_1FD10);  return result;}
room_138(){  int result;   char v1;   pthread_mutex_lock(&stru_1E9B0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_1FD38);  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_1D628);  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_1E988);  return result;}
room_139(){  int result;   char v1;   pthread_mutex_lock(&stru_1E9D8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_1FD60);  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_1D650);  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_1E9B0);  return result;}
room_140(){  int result;   char v1;   pthread_mutex_lock(&stru_1EA00);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_1EAC8);  return result;}
room_141(){  int result;   char v1;   pthread_mutex_lock(&stru_1EA28);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_1EA50);  return result;}
room_142(){  int result;   char v1;   pthread_mutex_lock(&stru_1EA50);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_1EA78);  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_1D6C8);  return result;}
room_143(){  pthread_mutex_lock(&stru_1EA78);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_144(){  pthread_mutex_lock(&stru_1EAA0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_145(){  int result;   char v1;   pthread_mutex_lock(&stru_1EAC8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_1D740);  return result;}
room_146(){  int result;   char v1;   pthread_mutex_lock(&stru_1EAF0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_1EA28);  return result;}
room_147(){  pthread_mutex_lock(&stru_1EB18);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_148(){  int result;   char v1;   pthread_mutex_lock(&stru_1EB40);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_1EB68);  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_1D7B8);  return result;}
room_149(){  pthread_mutex_lock(&stru_1EB68);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_150(){  pthread_mutex_lock(&stru_1EB90);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_151(){  pthread_mutex_lock(&stru_1EBB8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_152(){  int result;   char v1;   pthread_mutex_lock(&stru_1EBE0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_1E7F8);  return result;}
room_153(){  int result;   char v1;   pthread_mutex_lock(&stru_1EC08);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_1EC30);  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_1D880);  return result;}
room_154(){  pthread_mutex_lock(&stru_1EC30);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_155(){  int result;   char v1;   pthread_mutex_lock(&stru_1EC58);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_1E870);  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_1F040);  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_1EC80);  return result;}
room_156(){  int result;   char v1;   pthread_mutex_lock(&stru_1EC80);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_1EBB8);  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_20008);  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_1F068);  return result;}
room_157(){  int result;   char v1;   pthread_mutex_lock(&stru_1ECA8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_1EBE0);  return result;}
room_158(){  pthread_mutex_lock(&stru_1ECD0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_159(){  int result;   char v1;   pthread_mutex_lock(&stru_1ECF8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_1ECD0);  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_1D970);  return result;}
room_160(){  pthread_mutex_lock(&stru_1ED20);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_161(){  int result;   char v1;   pthread_mutex_lock(&stru_1ED48);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_1F130);  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_200D0);  return result;}
room_162(){  int result;   char v1;   pthread_mutex_lock(&stru_1ED70);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_1F158);  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_200F8);  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_1ED48);  return result;}
room_163(){  pthread_mutex_lock(&stru_1ED98);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_164(){  int result;   char v1;   pthread_mutex_lock(&stru_1EDC0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_1ED98);  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_1ECF8);  return result;}
room_165(){  pthread_mutex_lock(&stru_1EDE8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_166(){  int result;   char v1;   pthread_mutex_lock(&stru_1EE10);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_1EE38);  return result;}
room_167(){  int result;   char v1;   pthread_mutex_lock(&stru_1EE38);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_1EF00);  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_1ED70);  return result;}
room_168(){  pthread_mutex_lock(&stru_1EE60);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_169(){  int result;   char v1;   pthread_mutex_lock(&stru_1EE88);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_1F270);  return result;}
room_170(){  int result;   char v1;   pthread_mutex_lock(&stru_1EEB0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_1EED8);  return result;}
room_171(){  pthread_mutex_lock(&stru_1EED8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_172(){  pthread_mutex_lock(&stru_1EF00);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_173(){  int result;   char v1;   pthread_mutex_lock(&stru_1EF28);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_1DBA0);  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_1EB40);  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_202B0);  return result;}
room_174(){  pthread_mutex_lock(&stru_1EF50);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_175(){  pthread_mutex_lock(&stru_1EF78);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_176(){  pthread_mutex_lock(&stru_1EFA0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_177(){  pthread_mutex_lock(&stru_1EFC8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_178(){  int result;   char v1;   pthread_mutex_lock(&stru_1EFF0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_1EC08);  return result;}
room_179(){  int result;   char v1;   pthread_mutex_lock(&stru_1F018);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_1DC90);  return result;}
room_180(){  pthread_mutex_lock(&stru_1F040);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_181(){  int result;   char v1;   pthread_mutex_lock(&stru_1F068);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_1EFA0);  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_1F090);  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_1DCE0);  return result;}
room_182(){  pthread_mutex_lock(&stru_1F090);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_183(){  int result;   char v1;   pthread_mutex_lock(&stru_1F0B8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_1F180);  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_1EFF0);  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_20440);  return result;}
room_184(){  int result;   char v1;   pthread_mutex_lock(&stru_1F0E0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_1F0B8);  return result;}
room_185(){  int result;   char v1;   pthread_mutex_lock(&stru_1F108);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_20490);  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_1DD80);  return result;}
room_186(){  pthread_mutex_lock(&stru_1F130);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_187(){  pthread_mutex_lock(&stru_1F158);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_188(){  pthread_mutex_lock(&stru_1F180);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_189(){  int result;   char v1;   pthread_mutex_lock(&stru_1F1A8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_1DE20);  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_1F590);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_1EDC0);  return result;}
room_190(){  int result;   char v1;   pthread_mutex_lock(&stru_1F1D0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_1EDE8);  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_20558);  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_1F108);  return result;}
room_191(){  pthread_mutex_lock(&stru_1F1F8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_192(){  pthread_mutex_lock(&stru_1F220);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_193(){  int result;   char v1;   pthread_mutex_lock(&stru_1F248);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_205D0);  return result;}
room_194(){  int result;   char v1;   pthread_mutex_lock(&stru_1F270);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_1F338);  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_205F8);  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_1F1A8);  return result;}
room_195(){  pthread_mutex_lock(&stru_1F298);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_196(){  pthread_mutex_lock(&stru_1F2C0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_197(){  pthread_mutex_lock(&stru_1F2E8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_198(){  int result;   char v1;   pthread_mutex_lock(&stru_1F310);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_1EF28);  return result;}
room_199(){  pthread_mutex_lock(&stru_1F338);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_200(){  pthread_mutex_lock(&stru_1F360);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_201(){  int result;   char v1;   pthread_mutex_lock(&stru_1F388);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_20710);  return result;}
room_202(){  pthread_mutex_lock(&stru_1F3B0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_203(){  pthread_mutex_lock(&stru_1F3D8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_204(){  pthread_mutex_lock(&stru_1F400);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_205(){  pthread_mutex_lock(&stru_1F428);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_206(){  int result;   char v1;   pthread_mutex_lock(&stru_1F450);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_1F838);  return result;}
room_207(){  pthread_mutex_lock(&stru_1F478);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_208(){  int result;   char v1;   pthread_mutex_lock(&stru_1F4A0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_1F568);  return result;}
room_209(){  int result;   char v1;   pthread_mutex_lock(&stru_1F4C8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_1F0E0);  return result;}
room_210(){  pthread_mutex_lock(&stru_1F4F0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_211(){  int result;   char v1;   pthread_mutex_lock(&stru_1F518);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_1F540);  return result;}
room_212(){  int result;   char v1;   pthread_mutex_lock(&stru_1F540);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_1F608);  return result;}
room_213(){  int result;   char v1;   pthread_mutex_lock(&stru_1F568);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_1F630);  return result;}
room_214(){  pthread_mutex_lock(&stru_1F590);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_215(){  int result;   char v1;   pthread_mutex_lock(&stru_1F5B8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_1F680);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_1F1D0);  return result;}
room_216(){  int result;   char v1;   pthread_mutex_lock(&stru_1F5E0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_1E258);  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_1F6A8);  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_1F5B8);  return result;}
room_217(){  int result;   char v1;   pthread_mutex_lock(&stru_1F608);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_1E280);  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_1F5E0);  return result;}
room_218(){  int result;   char v1;   pthread_mutex_lock(&stru_1F630);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_1FA18);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_1F248);  return result;}
room_219(){  pthread_mutex_lock(&stru_1F658);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_220(){  pthread_mutex_lock(&stru_1F680);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_221(){  pthread_mutex_lock(&stru_1F6A8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_222(){  pthread_mutex_lock(&stru_1F6D0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_223(){  int result;   char v1;   pthread_mutex_lock(&stru_1F6F8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_1F310);  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_1FAE0);  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_1F6D0);  return result;}
room_224(){  pthread_mutex_lock(&stru_1F720);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_225(){  int result;   char v1;   pthread_mutex_lock(&stru_1F748);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_20AD0);  return result;}
room_226(){  int result;   char v1;   pthread_mutex_lock(&stru_1F770);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_1F388);  return result;}
room_227(){  int result;   char v1;   pthread_mutex_lock(&stru_1F798);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_1E410);  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_1F3B0);  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_1F770);  return result;}
room_228(){  pthread_mutex_lock(&stru_1F7C0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_229(){  int result;   char v1;   pthread_mutex_lock(&stru_1F7E8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_1F400);  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_1E460);  return result;}
room_230(){  pthread_mutex_lock(&stru_1F810);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_231(){  int result;   char v1;   pthread_mutex_lock(&stru_1F838);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_20BC0);  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_1F810);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_1F900);  return result;}
room_232(){  int result;   char v1;   pthread_mutex_lock(&stru_1F860);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_1F798);  return result;}
room_233(){  pthread_mutex_lock(&stru_1F888);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_234(){  int result;   char v1;   pthread_mutex_lock(&stru_1F8B0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_1F4C8);  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_1F7E8);  return result;}
room_235(){  int result;   char v1;   pthread_mutex_lock(&stru_1F8D8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_1F4F0);  return result;}
room_236(){  int result;   char v1;   pthread_mutex_lock(&stru_1F900);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_1F928);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_1F518);  return result;}
room_237(){  pthread_mutex_lock(&stru_1F928);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_238(){  pthread_mutex_lock(&stru_1F950);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_239(){  pthread_mutex_lock(&stru_1F978);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_240(){  int result;   char v1;   pthread_mutex_lock(&stru_1F9A0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_1F8D8);  return result;}
room_241(){  int result;   char v1;   pthread_mutex_lock(&stru_1F9C8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_1F9F0);  return result;}
room_242(){  pthread_mutex_lock(&stru_1F9F0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_243(){  pthread_mutex_lock(&stru_1FA18);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_244(){  int result;   char v1;   pthread_mutex_lock(&stru_1FA40);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_1F658);  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_20DC8);  return result;}
room_245(){  pthread_mutex_lock(&stru_1FA68);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_246(){  int result;   char v1;   pthread_mutex_lock(&stru_1FA90);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_1FA68);  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_20E18);  return result;}
room_247(){  pthread_mutex_lock(&stru_1FAB8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_248(){  int result;   char v1;   pthread_mutex_lock(&stru_1FAE0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_1E758);  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_1FB08);  return result;}
room_249(){  int result;   char v1;   pthread_mutex_lock(&stru_1FB08);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_1E780);  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_1FA40);  return result;}
room_250(){  pthread_mutex_lock(&stru_1FB30);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_251(){  int result;   char v1;   pthread_mutex_lock(&stru_1FB58);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_1FC20);  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_1FF40);  return result;}
room_252(){  pthread_mutex_lock(&stru_1FB80);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_253(){  int result;   char v1;   pthread_mutex_lock(&stru_1FBA8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_1FB80);  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_1FBD0);  return result;}
room_254(){  int result;   char v1;   pthread_mutex_lock(&stru_1FBD0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_1FC98);  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_20F58);  return result;}
room_255(){  int result;   char v1;   pthread_mutex_lock(&stru_1FBF8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_1FFE0);  return result;}
room_256(){  int result;   char v1;   pthread_mutex_lock(&stru_1FC20);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_20FA8);  return result;}
room_257(){  int result;   char v1;   pthread_mutex_lock(&stru_1FC48);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_20030);  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_20FD0);  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_1FC70);  return result;}
room_258(){  int result;   char v1;   pthread_mutex_lock(&stru_1FC70);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_1FBA8);  return result;}
room_259(){  pthread_mutex_lock(&stru_1FC98);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_260(){  int result;   char v1;   pthread_mutex_lock(&stru_1FCC0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_1E938);  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_21048);  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_1FBF8);  return result;}
room_261(){  int result;   char v1;   pthread_mutex_lock(&stru_1FCE8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_21070);  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_1FDB0);  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_1FCC0);  return result;}
room_262(){  int result;   char v1;   pthread_mutex_lock(&stru_1FD10);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_1FDD8);  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_1FC48);  return result;}
room_263(){  pthread_mutex_lock(&stru_1FD38);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_264(){  pthread_mutex_lock(&stru_1FD60);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_265(){  int result;   char v1;   pthread_mutex_lock(&stru_1FD88);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_1EA00);  return result;}
room_266(){  pthread_mutex_lock(&stru_1FDB0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_267(){  pthread_mutex_lock(&stru_1FDD8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_268(){  int result;   char v1;   pthread_mutex_lock(&stru_1FE00);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_201E8);  return result;}
room_269(){  int result;   char v1;   pthread_mutex_lock(&stru_1FE28);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_1FEF0);  return result;}
room_270(){  pthread_mutex_lock(&stru_1FE50);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_271(){  pthread_mutex_lock(&stru_1FE78);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_272(){  int result;   char v1;   pthread_mutex_lock(&stru_1FEA0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_1FE78);  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_1EB18);  return result;}
room_273(){  int result;   char v1;   pthread_mutex_lock(&stru_1FEC8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_21250);  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_1FEA0);  return result;}
room_274(){  int result;   char v1;   pthread_mutex_lock(&stru_1FEF0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_202D8);  return result;}
room_275(){  pthread_mutex_lock(&stru_1FF18);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_276(){  int result;   char v1;   pthread_mutex_lock(&stru_1FF40);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_1FF68);  return result;}
room_277(){  int result;   char v1;   pthread_mutex_lock(&stru_1FF68);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_212F0);  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_1FF90);  return result;}
room_278(){  int result;   char v1;   pthread_mutex_lock(&stru_1FF90);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_1FFB8);  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_20378);  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_21318);  return result;}
room_279(){  pthread_mutex_lock(&stru_1FFB8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_280(){  int result;   char v1;   pthread_mutex_lock(&stru_1FFE0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_1FF18);  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_21368);  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_1EC58);  return result;}
room_281(){  pthread_mutex_lock(&stru_20008);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_282(){  pthread_mutex_lock(&stru_20030);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_283(){  int result;   char v1;   pthread_mutex_lock(&stru_20058);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_20080);  return result;}
room_284(){  int result;   char v1;   pthread_mutex_lock(&stru_20080);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_21408);  return result;}
room_285(){  pthread_mutex_lock(&stru_200A8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_286(){  int result;   char v1;   pthread_mutex_lock(&stru_200D0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_21458);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_1FCE8);  return result;}
room_287(){  pthread_mutex_lock(&stru_200F8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_288(){  pthread_mutex_lock(&stru_20120);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_289(){  int result;   char v1;   pthread_mutex_lock(&stru_20148);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_20530);  return result;}
room_290(){  int result;   char v1;   pthread_mutex_lock(&stru_20170);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_200A8);  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_214F8);  return result;}
room_291(){  pthread_mutex_lock(&stru_20198);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_292(){  int result;   char v1;   pthread_mutex_lock(&stru_201C0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_205A8);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_20288);  return result;}
room_293(){  int result;   char v1;   pthread_mutex_lock(&stru_201E8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_20120);  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_1EE60);  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_201C0);  return result;}
room_294(){  int result;   char v1;   pthread_mutex_lock(&stru_20210);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_1EE88);  return result;}
room_295(){  int result;   char v1;   pthread_mutex_lock(&stru_20238);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_1EEB0);  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_1FE50);  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_20170);  return result;}
room_296(){  pthread_mutex_lock(&stru_20260);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_297(){  int result;   char v1;   pthread_mutex_lock(&stru_20288);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_21610);  return result;}
room_298(){  int result;   char v1;   pthread_mutex_lock(&stru_202B0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_1FEC8);  return result;}
room_299(){  int result;   char v1;   pthread_mutex_lock(&stru_202D8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_20210);  return result;}
room_300(){  int result;   char v1;   pthread_mutex_lock(&stru_20300);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_21688);  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_1EF78);  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_206E8);  return result;}
room_301(){  pthread_mutex_lock(&stru_20328);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_302(){  pthread_mutex_lock(&stru_20350);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_303(){  int result;   char v1;   pthread_mutex_lock(&stru_20378);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_20760);  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_203A0);  return result;}
room_304(){  int result;   char v1;   pthread_mutex_lock(&stru_203A0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_1F018);  return result;}
room_305(){  int result;   char v1;   pthread_mutex_lock(&stru_203C8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_20300);  return result;}
room_306(){  pthread_mutex_lock(&stru_203F0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_307(){  pthread_mutex_lock(&stru_20418);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_308(){  int result;   char v1;   pthread_mutex_lock(&stru_20440);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_20058);  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_20418);  return result;}
room_309(){  pthread_mutex_lock(&stru_20468);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_310(){  pthread_mutex_lock(&stru_20490);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_311(){  int result;   char v1;   pthread_mutex_lock(&stru_204B8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_204E0);  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_21840);  return result;}
room_312(){  pthread_mutex_lock(&stru_204E0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_313(){  pthread_mutex_lock(&stru_20508);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_314(){  int result;   char v1;   pthread_mutex_lock(&stru_20530);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_20468);  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_218B8);  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_20918);  return result;}
room_315(){  pthread_mutex_lock(&stru_20558);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_316(){  int result;   char v1;   pthread_mutex_lock(&stru_20580);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_20198);  return result;}
room_317(){  pthread_mutex_lock(&stru_205A8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_318(){  int result;   char v1;   pthread_mutex_lock(&stru_205D0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_209B8);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_20698);  return result;}
room_319(){  pthread_mutex_lock(&stru_205F8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_320(){  int result;   char v1;   pthread_mutex_lock(&stru_20620);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_1F298);  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_219A8);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_20238);  return result;}
room_321(){  int result;   char v1;   pthread_mutex_lock(&stru_20648);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_20A30);  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_20260);  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_20620);  return result;}
room_322(){  int result;   char v1;   pthread_mutex_lock(&stru_20670);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_1F2E8);  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_20648);  return result;}
room_323(){  int result;   char v1;   pthread_mutex_lock(&stru_20698);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_206C0);  return result;}
room_324(){  int result;   char v1;   pthread_mutex_lock(&stru_206C0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_20AA8);  return result;}
room_325(){  int result;   char v1;   pthread_mutex_lock(&stru_206E8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_1F360);  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_21A70);  return result;}
room_326(){  int result;   char v1;   pthread_mutex_lock(&stru_20710);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_20328);  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_21A98);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_207D8);  return result;}
room_327(){  int result;   char v1;   pthread_mutex_lock(&stru_20738);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_20350);  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_21AC0);  return result;}
room_328(){  pthread_mutex_lock(&stru_20760);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_329(){  pthread_mutex_lock(&stru_20788);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_330(){  pthread_mutex_lock(&stru_207B0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_331(){  int result;   char v1;   pthread_mutex_lock(&stru_207D8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_203F0);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_208A0);  return result;}
room_332(){  pthread_mutex_lock(&stru_20800);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_333(){  int result;   char v1;   pthread_mutex_lock(&stru_20828);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_1F4A0);  return result;}
room_334(){  int result;   char v1;   pthread_mutex_lock(&stru_20850);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_20788);  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_20828);  return result;}
room_335(){  pthread_mutex_lock(&stru_20878);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_336(){  int result;   char v1;   pthread_mutex_lock(&stru_208A0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_204B8);  return result;}
room_337(){  pthread_mutex_lock(&stru_208C8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_338(){  pthread_mutex_lock(&stru_208F0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_339(){  int result;   char v1;   pthread_mutex_lock(&stru_20918);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_209E0);  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_20850);  return result;}
room_340(){  int result;   char v1;   pthread_mutex_lock(&stru_20940);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_20A08);  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_20878);  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_20968);  return result;}
room_341(){  int result;   char v1;   pthread_mutex_lock(&stru_20968);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_21CF0);  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_20D50);  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_20990);  return result;}
room_342(){  int result;   char v1;   pthread_mutex_lock(&stru_20990);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_208C8);  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_20A58);  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_20D78);  return result;}
room_343(){  pthread_mutex_lock(&stru_209B8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_344(){  pthread_mutex_lock(&stru_209E0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_345(){  pthread_mutex_lock(&stru_20A08);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_346(){  pthread_mutex_lock(&stru_20A30);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_347(){  pthread_mutex_lock(&stru_20A58);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_348(){  pthread_mutex_lock(&stru_20A80);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_349(){  int result;   char v1;   pthread_mutex_lock(&stru_20AA8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_1F720);  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_20A80);  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_20E90);  return result;}
room_350(){  int result;   char v1;   pthread_mutex_lock(&stru_20AD0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_20B98);  return result;}
room_351(){  pthread_mutex_lock(&stru_20AF8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_352(){  int result;   char v1;   pthread_mutex_lock(&stru_20B20);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_20AF8);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_20738);  return result;}
room_353(){  int result;   char v1;   pthread_mutex_lock(&stru_20B48);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_20C10);  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_1F7C0);  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_20B20);  return result;}
room_354(){  pthread_mutex_lock(&stru_20B70);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_355(){  int result;   char v1;   pthread_mutex_lock(&stru_20B98);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_207B0);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_20C60);  return result;}
room_356(){  pthread_mutex_lock(&stru_20BC0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_357(){  int result;   char v1;   pthread_mutex_lock(&stru_20BE8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_20800);  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_1F860);  return result;}
room_358(){  pthread_mutex_lock(&stru_20C10);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_359(){  int result;   char v1;   pthread_mutex_lock(&stru_20C38);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_20B70);  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_1F8B0);  return result;}
room_360(){  int result;   char v1;   pthread_mutex_lock(&stru_20C60);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_20D28);  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_20C88);  return result;}
room_361(){  int result;   char v1;   pthread_mutex_lock(&stru_20C88);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_22010);  return result;}
room_362(){  pthread_mutex_lock(&stru_20CB0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_363(){  int result;   char v1;   pthread_mutex_lock(&stru_20CD8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_22060);  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_1F950);  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_20DA0);  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_208F0);  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_20CB0);  return result;}
room_364(){  int result;   char v1;   pthread_mutex_lock(&stru_20D00);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_20CD8);  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_20C38);  return result;}
room_365(){  pthread_mutex_lock(&stru_20D28);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_366(){  pthread_mutex_lock(&stru_20D50);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_367(){  int result;   char v1;   pthread_mutex_lock(&stru_20D78);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_20E40);  return result;}
room_368(){  pthread_mutex_lock(&stru_20DA0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_369(){  int result;   char v1;   pthread_mutex_lock(&stru_20DC8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_20D00);  return result;}
room_370(){  pthread_mutex_lock(&stru_20DF0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_371(){  int result;   char v1;   pthread_mutex_lock(&stru_20E18);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_20DF0);  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_221A0);  return result;}
room_372(){  int result;   char v1;   pthread_mutex_lock(&stru_20E40);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_1FAB8);  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_221C8);  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_20E68);  return result;}
room_373(){  int result;   char v1;   pthread_mutex_lock(&stru_20E68);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_221F0);  return result;}
room_374(){  int result;   char v1;   pthread_mutex_lock(&stru_20E90);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_22218);  return result;}
room_375(){  int result;   char v1;   pthread_mutex_lock(&stru_20EB8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_22240);  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_212A0);  return result;}
room_376(){  int result;   char v1;   pthread_mutex_lock(&stru_20EE0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_20F08);  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_1FB58);  return result;}
room_377(){  pthread_mutex_lock(&stru_20F08);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_378(){  pthread_mutex_lock(&stru_20F30);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_379(){  int result;   char v1;   pthread_mutex_lock(&stru_20F58);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_20F30);  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_21020);  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_21340);  return result;}
room_380(){  int result;   char v1;   pthread_mutex_lock(&stru_20F80);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_20EB8);  return result;}
room_381(){  int result;   char v1;   pthread_mutex_lock(&stru_20FA8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_20F80);  return result;}
room_382(){  pthread_mutex_lock(&stru_20FD0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_383(){  pthread_mutex_lock(&stru_20FF8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_384(){  pthread_mutex_lock(&stru_21020);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_385(){  pthread_mutex_lock(&stru_21048);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_386(){  pthread_mutex_lock(&stru_21070);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_387(){  int result;   char v1;   pthread_mutex_lock(&stru_21098);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_22420);  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_210C0);  return result;}
room_388(){  int result;   char v1;   pthread_mutex_lock(&stru_210C0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_22448);  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_20FF8);  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_210E8);  return result;}
room_389(){  int result;   char v1;   pthread_mutex_lock(&stru_210E8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_211B0);  return result;}
room_390(){  int result;   char v1;   pthread_mutex_lock(&stru_21110);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_21138);  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_1FD88);  return result;}
room_391(){  pthread_mutex_lock(&stru_21138);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_392(){  pthread_mutex_lock(&stru_21160);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_393(){  int result;   char v1;   pthread_mutex_lock(&stru_21188);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_21160);  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_1FE00);  return result;}
room_394(){  int result;   char v1;   pthread_mutex_lock(&stru_211B0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_21278);  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_1FE28);  return result;}
room_395(){  int result;   char v1;   pthread_mutex_lock(&stru_211D8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_21200);  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_215C0);  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_21110);  return result;}
room_396(){  pthread_mutex_lock(&stru_21200);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_397(){  pthread_mutex_lock(&stru_21228);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_398(){  pthread_mutex_lock(&stru_21250);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_399(){  pthread_mutex_lock(&stru_21278);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_400(){  pthread_mutex_lock(&stru_212A0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_401(){  int result;   char v1;   pthread_mutex_lock(&stru_212C8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_20EE0);  return result;}
room_402(){  int result;   char v1;   pthread_mutex_lock(&stru_212F0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_22678);  return result;}
room_403(){  pthread_mutex_lock(&stru_21318);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_404(){  int result;   char v1;   pthread_mutex_lock(&stru_21340);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_21728);  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_226C8);  return result;}
room_405(){  pthread_mutex_lock(&stru_21368);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_406(){  pthread_mutex_lock(&stru_21390);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_407(){  pthread_mutex_lock(&stru_213B8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_408(){  pthread_mutex_lock(&stru_213E0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_409(){  pthread_mutex_lock(&stru_21408);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_410(){  pthread_mutex_lock(&stru_21430);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_411(){  pthread_mutex_lock(&stru_21458);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_412(){  int result;   char v1;   pthread_mutex_lock(&stru_21480);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_213B8);  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_22808);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_21098);  return result;}
room_413(){  int result;   char v1;   pthread_mutex_lock(&stru_214A8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_21570);  return result;}
room_414(){  int result;   char v1;   pthread_mutex_lock(&stru_214D0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_20148);  return result;}
room_415(){  int result;   char v1;   pthread_mutex_lock(&stru_214F8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_22880);  return result;}
room_416(){  pthread_mutex_lock(&stru_21520);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_417(){  int result;   char v1;   pthread_mutex_lock(&stru_21548);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_21520);  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_21930);  return result;}
room_418(){  int result;   char v1;   pthread_mutex_lock(&stru_21570);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_21638);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_21188);  return result;}
room_419(){  int result;   char v1;   pthread_mutex_lock(&stru_21598);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_21660);  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_21980);  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_214D0);  return result;}
room_420(){  pthread_mutex_lock(&stru_215C0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_421(){  pthread_mutex_lock(&stru_215E8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_422(){  int result;   char v1;   pthread_mutex_lock(&stru_21610);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_21548);  return result;}
room_423(){  pthread_mutex_lock(&stru_21638);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_424(){  pthread_mutex_lock(&stru_21660);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_425(){  pthread_mutex_lock(&stru_21688);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_426(){  int result;   char v1;   pthread_mutex_lock(&stru_216B0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_21778);  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_216D8);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_212C8);  return result;}
room_427(){  pthread_mutex_lock(&stru_216D8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_428(){  pthread_mutex_lock(&stru_21700);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_429(){  pthread_mutex_lock(&stru_21728);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_430(){  int result;   char v1;   pthread_mutex_lock(&stru_21750);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_203C8);  return result;}
room_431(){  pthread_mutex_lock(&stru_21778);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_432(){  int result;   char v1;   pthread_mutex_lock(&stru_217A0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_217C8);  return result;}
room_433(){  int result;   char v1;   pthread_mutex_lock(&stru_217C8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_213E0);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_21890);  return result;}
room_434(){  pthread_mutex_lock(&stru_217F0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_435(){  int result;   char v1;   pthread_mutex_lock(&stru_21818);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_22BA0);  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_21750);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_21430);  return result;}
room_436(){  int result;   char v1;   pthread_mutex_lock(&stru_21840);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_21868);  return result;}
room_437(){  int result;   char v1;   pthread_mutex_lock(&stru_21868);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_21480);  return result;}
room_438(){  int result;   char v1;   pthread_mutex_lock(&stru_21890);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_21958);  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_20508);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_214A8);  return result;}
room_439(){  pthread_mutex_lock(&stru_218B8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_440(){  int result;   char v1;   pthread_mutex_lock(&stru_218E0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_22C68);  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_21818);  return result;}
room_441(){  int result;   char v1;   pthread_mutex_lock(&stru_21908);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_20580);  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_218E0);  return result;}
room_442(){  int result;   char v1;   pthread_mutex_lock(&stru_21930);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_22CB8);  return result;}
room_443(){  pthread_mutex_lock(&stru_21958);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_444(){  pthread_mutex_lock(&stru_21980);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_445(){  pthread_mutex_lock(&stru_219A8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_446(){  int result;   char v1;   pthread_mutex_lock(&stru_219D0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_22D58);  return result;}
room_447(){  int result;   char v1;   pthread_mutex_lock(&stru_219F8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_20670);  return result;}
room_448(){  int result;   char v1;   pthread_mutex_lock(&stru_21A20);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_22DA8);  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_219F8);  return result;}
room_449(){  int result;   char v1;   pthread_mutex_lock(&stru_21A48);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_22DD0);  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_21A20);  return result;}
room_450(){  int result;   char v1;   pthread_mutex_lock(&stru_21A70);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_22DF8);  return result;}
room_451(){  pthread_mutex_lock(&stru_21A98);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_452(){  int result;   char v1;   pthread_mutex_lock(&stru_21AC0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_21B88);  return result;}
room_453(){  int result;   char v1;   pthread_mutex_lock(&stru_21AE8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_21700);  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_21ED0);  return result;}
room_454(){  int result;   char v1;   pthread_mutex_lock(&stru_21B10);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_22E98);  return result;}
room_455(){  int result;   char v1;   pthread_mutex_lock(&stru_21B38);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_21F20);  return result;}
room_456(){  pthread_mutex_lock(&stru_21B60);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_457(){  int result;   char v1;   pthread_mutex_lock(&stru_21B88);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_21F70);  return result;}
room_458(){  int result;   char v1;   pthread_mutex_lock(&stru_21BB0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_21AE8);  return result;}
room_459(){  int result;   char v1;   pthread_mutex_lock(&stru_21BD8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_217F0);  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_21FC0);  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_21B10);  return result;}
room_460(){  pthread_mutex_lock(&stru_21C00);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_461(){  pthread_mutex_lock(&stru_21C28);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_462(){  int result;   char v1;   pthread_mutex_lock(&stru_21C50);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_21D18);  return result;}
room_463(){  pthread_mutex_lock(&stru_21C78);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_464(){  int result;   char v1;   pthread_mutex_lock(&stru_21CA0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_21BD8);  return result;}
room_465(){  int result;   char v1;   pthread_mutex_lock(&stru_21CC8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_21C00);  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_23050);  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_20940);  return result;}
room_466(){  pthread_mutex_lock(&stru_21CF0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_467(){  int result;   char v1;   pthread_mutex_lock(&stru_21D18);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_22100);  return result;}
room_468(){  pthread_mutex_lock(&stru_21D40);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_469(){  int result;   char v1;   pthread_mutex_lock(&stru_21D68);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_230F0);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_21E30);  return result;}
room_470(){  pthread_mutex_lock(&stru_21D90);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_471(){  int result;   char v1;   pthread_mutex_lock(&stru_21DB8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_23140);  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_21D90);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_219D0);  return result;}
room_472(){  pthread_mutex_lock(&stru_21DE0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_473(){  pthread_mutex_lock(&stru_21E08);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_474(){  int result;   char v1;   pthread_mutex_lock(&stru_21E30);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_231B8);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_21A48);  return result;}
room_475(){  int result;   char v1;   pthread_mutex_lock(&stru_21E58);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_231E0);  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_21E80);  return result;}
room_476(){  int result;   char v1;   pthread_mutex_lock(&stru_21E80);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_23208);  return result;}
room_477(){  pthread_mutex_lock(&stru_21EA8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_478(){  int result;   char v1;   pthread_mutex_lock(&stru_21ED0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_21EF8);  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_21EA8);  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_20B48);  return result;}
room_479(){  pthread_mutex_lock(&stru_21EF8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_480(){  int result;   char v1;   pthread_mutex_lock(&stru_21F20);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_21E58);  return result;}
room_481(){  pthread_mutex_lock(&stru_21F48);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_482(){  int result;   char v1;   pthread_mutex_lock(&stru_21F70);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_22038);  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_21F98);  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_20BE8);  return result;}
room_483(){  pthread_mutex_lock(&stru_21F98);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_484(){  pthread_mutex_lock(&stru_21FC0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_485(){  pthread_mutex_lock(&stru_21FE8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_486(){  int result;   char v1;   pthread_mutex_lock(&stru_22010);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_21C28);  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_21F48);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_220D8);  return result;}
room_487(){  pthread_mutex_lock(&stru_22038);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_488(){  int result;   char v1;   pthread_mutex_lock(&stru_22060);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_233E8);  return result;}
room_489(){  pthread_mutex_lock(&stru_22088);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_490(){  int result;   char v1;   pthread_mutex_lock(&stru_220B0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_22178);  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_23438);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_21CC8);  return result;}
room_491(){  int result;   char v1;   pthread_mutex_lock(&stru_220D8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_220B0);  return result;}
room_492(){  pthread_mutex_lock(&stru_22100);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_493(){  pthread_mutex_lock(&stru_22128);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_494(){  int result;   char v1;   pthread_mutex_lock(&stru_22150);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_22088);  if ( v1 == 102 )    result = pthread_mutex_unlock(&stru_234D8);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_21D68);  return result;}
room_495(){  pthread_mutex_lock(&stru_22178);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_496(){  int result;   char v1;   pthread_mutex_lock(&stru_221A0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_21DB8);  return result;}
room_497(){  pthread_mutex_lock(&stru_221C8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_498(){  int result;   char v1;   pthread_mutex_lock(&stru_221F0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_21E08);  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_22128);  if ( v1 == 102 )    return pthread_mutex_unlock(&stru_23578);  return result;}
room_499(){  int result;   char v1;   pthread_mutex_lock(&stru_22218);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_22150);  return result;}
room_500(){  pthread_mutex_lock(&stru_22240);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_501(){  int result;   char v1;   pthread_mutex_lock(&stru_22268);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_22290);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_22330);  return result;}
room_502(){  pthread_mutex_lock(&stru_22290);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_503(){  pthread_mutex_lock(&stru_222B8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_504(){  pthread_mutex_lock(&stru_222E0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_505(){  pthread_mutex_lock(&stru_22308);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_506(){  int result;   char v1;   pthread_mutex_lock(&stru_22330);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_223F8);  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_22358);  return result;}
room_507(){  int result;   char v1;   pthread_mutex_lock(&stru_22358);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_22740);  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_22380);  return result;}
room_508(){  int result;   char v1;   pthread_mutex_lock(&stru_22380);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_223A8);  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_22768);  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_222B8);  return result;}
room_509(){  pthread_mutex_lock(&stru_223A8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_510(){  pthread_mutex_lock(&stru_223D0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_511(){  int result;   char v1;   pthread_mutex_lock(&stru_223F8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_223D0);  return result;}
room_512(){  pthread_mutex_lock(&stru_22420);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_513(){  pthread_mutex_lock(&stru_22448);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_514(){  pthread_mutex_lock(&stru_22470);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_515(){  pthread_mutex_lock(&stru_22498);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_516(){  pthread_mutex_lock(&stru_224C0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_517(){  int result;   char v1;   pthread_mutex_lock(&stru_224E8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_22510);  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_224C0);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_225B0);  return result;}
room_518(){  pthread_mutex_lock(&stru_22510);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_519(){  int result;   char v1;   pthread_mutex_lock(&stru_22538);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_22470);  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_22920);  return result;}
room_520(){  int result;   char v1;   pthread_mutex_lock(&stru_22560);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_22498);  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_211D8);  return result;}
room_521(){  pthread_mutex_lock(&stru_22588);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_522(){  int result;   char v1;   pthread_mutex_lock(&stru_225B0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_22588);  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_21228);  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_225D8);  return result;}
room_523(){  int result;   char v1;   pthread_mutex_lock(&stru_225D8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_22600);  return result;}
room_524(){  int result;   char v1;   pthread_mutex_lock(&stru_22600);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_229E8);  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_22538);  return result;}
room_525(){  int result;   char v1;   pthread_mutex_lock(&stru_22628);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_226F0);  return result;}
room_526(){  int result;   char v1;   pthread_mutex_lock(&stru_22650);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_22268);  return result;}
room_527(){  pthread_mutex_lock(&stru_22678);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_528(){  pthread_mutex_lock(&stru_226A0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_529(){  int result;   char v1;   pthread_mutex_lock(&stru_226C8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_222E0);  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_22AB0);  return result;}
room_530(){  int result;   char v1;   pthread_mutex_lock(&stru_226F0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_22308);  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_22718);  return result;}
room_531(){  int result;   char v1;   pthread_mutex_lock(&stru_22718);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_22B00);  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_21390);  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_22650);  return result;}
room_532(){  pthread_mutex_lock(&stru_22740);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_533(){  int result;   char v1;   pthread_mutex_lock(&stru_22768);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_22790);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_22830);  return result;}
room_534(){  pthread_mutex_lock(&stru_22790);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_535(){  pthread_mutex_lock(&stru_227B8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_536(){  pthread_mutex_lock(&stru_227E0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_537(){  pthread_mutex_lock(&stru_22808);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_538(){  int result;   char v1;   pthread_mutex_lock(&stru_22830);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_22858);  return result;}
room_539(){  int result;   char v1;   pthread_mutex_lock(&stru_22858);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_22C40);  return result;}
room_540(){  int result;   char v1;   pthread_mutex_lock(&stru_22880);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_227B8);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_22948);  return result;}
room_541(){  pthread_mutex_lock(&stru_228A8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_542(){  int result;   char v1;   pthread_mutex_lock(&stru_228D0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_228F8);  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_228A8);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_224E8);  return result;}
room_543(){  pthread_mutex_lock(&stru_228F8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_544(){  int result;   char v1;   pthread_mutex_lock(&stru_22920);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_22D08);  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_21598);  return result;}
room_545(){  int result;   char v1;   pthread_mutex_lock(&stru_22948);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_22560);  return result;}
room_546(){  int result;   char v1;   pthread_mutex_lock(&stru_22970);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_22998);  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_215E8);  return result;}
room_547(){  int result;   char v1;   pthread_mutex_lock(&stru_22998);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_229C0);  return result;}
room_548(){  pthread_mutex_lock(&stru_229C0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_549(){  pthread_mutex_lock(&stru_229E8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_550(){  int result;   char v1;   pthread_mutex_lock(&stru_22A10);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_22AD8);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_22628);  return result;}
room_551(){  int result;   char v1;   pthread_mutex_lock(&stru_22A38);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_216B0);  return result;}
room_552(){  pthread_mutex_lock(&stru_22A60);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_553(){  int result;   char v1;   pthread_mutex_lock(&stru_22A88);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_226A0);  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_22A60);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_22B50);  return result;}
room_554(){  int result;   char v1;   pthread_mutex_lock(&stru_22AB0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_22B78);  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_22A88);  return result;}
room_555(){  pthread_mutex_lock(&stru_22AD8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_556(){  pthread_mutex_lock(&stru_22B00);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_557(){  int result;   char v1;   pthread_mutex_lock(&stru_22B28);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_217A0);  return result;}
room_558(){  int result;   char v1;   pthread_mutex_lock(&stru_22B50);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_22B28);  return result;}
room_559(){  pthread_mutex_lock(&stru_22B78);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_560(){  pthread_mutex_lock(&stru_22BA0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_561(){  int result;   char v1;   pthread_mutex_lock(&stru_22BC8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_227E0);  return result;}
room_562(){  int result;   char v1;   pthread_mutex_lock(&stru_22BF0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_22BC8);  return result;}
room_563(){  pthread_mutex_lock(&stru_22C18);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_564(){  int result;   char v1;   pthread_mutex_lock(&stru_22C40);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_23028);  return result;}
room_565(){  int result;   char v1;   pthread_mutex_lock(&stru_22C68);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_22D30);  return result;}
room_566(){  int result;   char v1;   pthread_mutex_lock(&stru_22C90);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_21908);  return result;}
room_567(){  int result;   char v1;   pthread_mutex_lock(&stru_22CB8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_228D0);  return result;}
room_568(){  pthread_mutex_lock(&stru_22CE0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_569(){  pthread_mutex_lock(&stru_22D08);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_570(){  int result;   char v1;   pthread_mutex_lock(&stru_22D30);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_23118);  return result;}
room_571(){  int result;   char v1;   pthread_mutex_lock(&stru_22D58);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_22C90);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_22970);  return result;}
room_572(){  pthread_mutex_lock(&stru_22D80);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_573(){  int result;   char v1;   pthread_mutex_lock(&stru_22DA8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_23190);  return result;}
room_574(){  pthread_mutex_lock(&stru_22DD0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_575(){  int result;   char v1;   pthread_mutex_lock(&stru_22DF8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_22A10);  return result;}
room_576(){  int result;   char v1;   pthread_mutex_lock(&stru_22E20);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_22A38);  return result;}
room_577(){  pthread_mutex_lock(&stru_22E48);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_578(){  pthread_mutex_lock(&stru_22E70);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_579(){  int result;   char v1;   pthread_mutex_lock(&stru_22E98);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_23280);  return result;}
room_580(){  int result;   char v1;   pthread_mutex_lock(&stru_22EC0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_21B38);  return result;}
room_581(){  int result;   char v1;   pthread_mutex_lock(&stru_22EE8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_21B60);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_22FB0);  return result;}
room_582(){  int result;   char v1;   pthread_mutex_lock(&stru_22F10);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_22E48);  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_22EE8);  return result;}
room_583(){  int result;   char v1;   pthread_mutex_lock(&stru_22F38);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_22E70);  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_22F60);  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_21BB0);  return result;}
room_584(){  pthread_mutex_lock(&stru_22F60);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_585(){  int result;   char v1;   pthread_mutex_lock(&stru_22F88);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_22EC0);  return result;}
room_586(){  int result;   char v1;   pthread_mutex_lock(&stru_22FB0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_22FD8);  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_23398);  return result;}
room_587(){  int result;   char v1;   pthread_mutex_lock(&stru_22FD8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_22BF0);  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_21C50);  return result;}
room_588(){  int result;   char v1;   pthread_mutex_lock(&stru_23000);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_21C78);  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_22C18);  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_22F38);  return result;}
room_589(){  int result;   char v1;   pthread_mutex_lock(&stru_23028);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    result = pthread_mutex_unlock(&stru_23410);  if ( v1 == 98 )    return pthread_mutex_unlock(&stru_21CA0);  return result;}
room_590(){  pthread_mutex_lock(&stru_23050);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_591(){  pthread_mutex_lock(&stru_23078);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_592(){  int result;   char v1;   pthread_mutex_lock(&stru_230A0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    return pthread_mutex_unlock(&stru_230C8);  return result;}
room_593(){  int result;   char v1;   pthread_mutex_lock(&stru_230C8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_22CE0);  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_21D40);  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_23000);  return result;}
room_594(){  pthread_mutex_lock(&stru_230F0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_595(){  int result;   char v1;   pthread_mutex_lock(&stru_23118);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_23500);  return result;}
room_596(){  pthread_mutex_lock(&stru_23140);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_597(){  int result;   char v1;   pthread_mutex_lock(&stru_23168);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_21DE0);  if ( v1 == 111 )    result = pthread_mutex_unlock(&stru_22D80);  if ( v1 == 100 )    return pthread_mutex_unlock(&stru_230A0);  return result;}
room_598(){  pthread_mutex_lock(&stru_23190);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_599(){  int result;   char v1;   pthread_mutex_lock(&stru_231B8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 105 )    return pthread_mutex_unlock(&stru_235A0);  return result;}
room_600(){  pthread_mutex_lock(&stru_231E0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_601(){  int result;   char v1;   pthread_mutex_lock(&stru_23208);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_22E20);  return result;}
room_602(){  pthread_mutex_lock(&stru_23230);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_603(){  int result;   char v1;   pthread_mutex_lock(&stru_23258);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_23230);  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_23320);  return result;}
room_604(){  int result;   char v1;   pthread_mutex_lock(&stru_23280);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_23258);  return result;}
room_605(){  pthread_mutex_lock(&stru_232A8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_606(){  pthread_mutex_lock(&stru_232D0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_607(){  int result;   char v1;   pthread_mutex_lock(&stru_232F8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_232D0);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_22F10);  return result;}
room_608(){  int result;   char v1;   pthread_mutex_lock(&stru_23320);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_23348);  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_232F8);  return result;}
room_609(){  pthread_mutex_lock(&stru_23348);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_610(){  int result;   char v1;   pthread_mutex_lock(&stru_23370);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_232A8);  if ( v1 == 98 )    result = pthread_mutex_unlock(&stru_21FE8);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_22F88);  return result;}
room_611(){  int result;   char v1;   pthread_mutex_lock(&stru_23398);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_23460);  if ( v1 == 114 )    result = pthread_mutex_unlock(&stru_233C0);  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_23370);  return result;}
room_612(){  pthread_mutex_lock(&stru_233C0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_613(){  int result;   char v1;   pthread_mutex_lock(&stru_233E8);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    return pthread_mutex_unlock(&stru_234B0);  return result;}
room_614(){  pthread_mutex_lock(&stru_23410);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_615(){  pthread_mutex_lock(&stru_23438);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_616(){  int result;   char v1;   pthread_mutex_lock(&stru_23460);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_23078);  return result;}
room_617(){  pthread_mutex_lock(&stru_23488);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_618(){  pthread_mutex_lock(&stru_234B0);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_619(){  pthread_mutex_lock(&stru_234D8);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_620(){  pthread_mutex_lock(&stru_23500);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_621(){  pthread_mutex_lock(&stru_23528);  TEXT[PTR] = getchar();  return (unsigned int)++PTR;}
room_622(){  int result;   char v1;   pthread_mutex_lock(&stru_23550);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    result = pthread_mutex_unlock(&stru_23528);  if ( v1 == 100 )    result = pthread_mutex_unlock(&stru_23488);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_23168);  return result;}
room_623(){  int result;   char v1;   pthread_mutex_lock(&stru_23578);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 108 )    return pthread_mutex_unlock(&stru_23550);  return result;}
room_624(){  int result;   char v1;   pthread_mutex_lock(&stru_235A0);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 114 )    return pthread_mutex_unlock(&exit_door);  return result;}
