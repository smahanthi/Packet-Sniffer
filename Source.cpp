#include <gtk/gtk.h>
#include <gtksourceview/gtksourceview.h>
#include "sniff.h"
GtkBuilder              *builder;
GtkWidget               *textview2;
GtkTextBuffer           *textbuf2;
GtkTextIter              iter2,end2;
char buf[1024];

 void 
 callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
    
  static int count = 1;
  int i=0,j=0;
 
  gtk_text_buffer_insert(textbuf2, &end2 ,"\n packet number\n", -1);
  snprintf(buf,BUF_SIZE,"%d",count++);
  gtk_text_buffer_insert(textbuf2, &end2 ,buf, -1);

  gtk_text_buffer_insert(textbuf2, &end2 ,"\n length of this packet is ", -1);
  snprintf(buf,BUF_SIZE,"%d",pkthdr->len);
  gtk_text_buffer_insert(textbuf2, &end2 ,buf, -1);

  gtk_text_buffer_insert(textbuf2, &end2 ,"\n Payload \n", -1);
 for(j=0;j<pkthdr->len;j++)
 {
  if(isprint(packet[j]))
  {
    snprintf(buf,BUF_SIZE,"%c",packet[j]);
    gtk_text_buffer_insert(textbuf2, &end2 ,buf, -1);
  }
  else
   snprintf(buf,BUF_SIZE,".",packet[j]);
   gtk_text_buffer_insert(textbuf2, &end2 ,buf, -1);

  if ((i%16==0 && i!=0) || i==pkthdr->len-1)
   {
    gtk_text_buffer_insert(textbuf2, &end2 ," \n  ", -1); 
   } 
    

 } 




  /*printf("\nPacket number [%d], length of this packet is: %d\n", count++, pkthdr->len);

  printf("Payload:\n");
  for(i=0;i<pkthdr->len;i++) 
    {
     if(isprint(packet[i]))
       printf("%c ",packet[i]);
     else
       printf(" . ",packet[i]);
       if((i%16==0 && i!=0) || i==pkthdr->len-1)
       printf("\n");
   }*/

}

 void
 on_start_capture(GtkWidget *button,GtkWidget *entry1)
 {
     //GtkBuilder              *builder;
     GtkWidget               *entry2;
     

    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;        /* to hold compiled program */
    bpf_u_int32 pMask;            /* subnet mask */
    bpf_u_int32 pNet;             /* ip address*/
    pcap_if_t *alldevs, *d;
    char dev_buff[64] = {0};
    int i =0;


     entry2= GTK_WIDGET (gtk_builder_get_object (builder, "entry2"));
     const gchar *ip_num = gtk_entry_get_text(GTK_ENTRY (entry2));
    

      const gchar *filter = gtk_entry_get_text(GTK_ENTRY (entry1));
    

    dev="wlan0";
     pcap_lookupnet(dev, &pNet, &pMask, errbuf);

    // Now, open device for sniffing
    descr = pcap_open_live(dev, BUFSIZ, 1,-1, errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_live() failed due to [%s]\n", errbuf);
        //return -1;
    }

    // Compile the filter expression
    if(pcap_compile(descr, &fp, filter, 0, pNet) == -1)
    {
        printf("\npcap_compile() failed\n");
        //return -1;
    }

    // Set the filter compiled above
    if(pcap_setfilter(descr, &fp) == -1)
    {
        printf("\npcap_setfilter() failed\n");
        exit(1);
    }

    // For every packet received, call the callback function
    // For now, maximum limit on number of packets is specified
    // by user.
    pcap_loop(descr,atoi(ip_num), callback, NULL);

    printf("\nDone with packet sniffing!\n");
    //return 0;
}
 
 void 
on_destroy1 (GtkWidget *widget,
            GdkEvent  *event,
            gpointer   user_data)  
{
        gtk_main_quit();
}
void
on_start(GtkButton *button,
             GtkTextView *textview1)            
{
    GtkWidget               *textview;
    GtkTextBuffer           *textbuf;
    GtkTextIter             iter,end;
    

    
         
      textbuf = gtk_text_view_get_buffer (GTK_TEXT_VIEW (textview1));
        
      gtk_text_buffer_get_iter_at_offset(textbuf, &iter, 0);

      gtk_text_buffer_get_end_iter(textbuf, &end);
    
    short port=3000,port_1=6000;

    /*  unsigned int a1=192;  //for manually specifying ip address
      unsigned int b1=168;
      unsigned int c1=255;
      unsigned int d1=255;
    
      unsigned int destination_address1=(a1<<24) | (b1<<16) | (c1<<8) | d1; */



 struct sockaddr_in address,dest;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
  //address.sin_addr.s_addr = htonl( destination_address );
    address.sin_port = htons( (unsigned short) port );




 int handle = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP ); 
    
    if ( handle <= 0 )
    {
        
      //  printf( " \n failed to create socket\n" );
      
        gtk_text_buffer_insert(textbuf, &end ,"\n failed to create socket\n", -1);
    
    }
else 
    { 
      
      //printf(" \n created socket");
      
      gtk_text_buffer_insert(textbuf, &end ,"\n created socket \n", -1);
    }


if ( bind( handle, (const struct sockaddr*) &address, sizeof(address) ) < 0 )
    {
        
        //printf( " \n failed to bind socket\n" );

        gtk_text_buffer_insert(textbuf, &end ,"\n failed to bind socket\n", -1);
        
    }
else 
    { 
        
     gtk_text_buffer_insert(textbuf, &end ," \n socket binded \n", -1);
       // printf(" \n socket binded \n");
    }

 
dest.sin_family=AF_INET;
//dest.sin_addr.s_addr = htonl( destination_address1 );

inet_pton(AF_INET, "255.255.255.255", &(dest.sin_addr));
dest.sin_port=htons((unsigned )port_1);

int status= connect(handle,(const struct sockaddr*)&dest,sizeof(dest));

if(status==0)
    {   
       
       // g_print("connection successful");
        gtk_text_buffer_insert(textbuf, &end ,"\nconnection successful \n A SNIFFER EXISTS ON THE NETWORK", -1);
    } 
else
    {
       // g_print("connection not successful");
        gtk_text_buffer_insert(textbuf, &end ,"\nconnection not successful , NO SNIFFER ON NETWORK \n", -1);
    }
}
int
main (int argc, char *argv[])
{
        //GtkBuilder              *builder;
        GtkWidget               *window1;
        GtkWidget               *button1;
        GtkWidget               *textview;
        GtkTextBuffer           *textbuf;

        
        gtk_init (&argc, &argv);
        
        builder = gtk_builder_new ();
        gtk_builder_add_from_file (builder, "test1.glade", NULL);

        window1 = GTK_WIDGET (gtk_builder_get_object (builder, "window1"));
           gtk_window_set_default_size(GTK_WINDOW(window1), 500, 500);
           //g_signal_connect (window1, "destroy", G_CALLBACK(on_destroy1), NULL);
           gtk_builder_connect_signals (builder, NULL);
           //g_object_unref (G_OBJECT (builder));
           
           gtk_widget_show (window1);

         textview2=GTK_WIDGET(gtk_builder_get_object(builder,"textview2"));
         textbuf2 = gtk_text_view_get_buffer (GTK_TEXT_VIEW (textview2));
        
        gtk_text_buffer_get_iter_at_offset(textbuf2, &iter2, 0);
        gtk_text_buffer_get_end_iter(textbuf2, &end2);
        /*button1 = GTK_WIDGET (gtk_builder_get_object (builder, "buton1"));
           g_signal_connect (button1, "clicked", G_CALLBACK(on_start), NULL); */  

        gtk_main ();
        
        return 0;
}