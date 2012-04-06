#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>

#include <sys/resource.h>
#if ! defined(RLIMIT_NOFILE) && defined(RLIMIT_OFILE)
#define RLIMIT_NOFILE RLIMIT_OFILE
#endif

#include <assert.h>
#define MAX_FD 64000

#define CLIENT_PORT "800"
#define ADMIN_PORT "801"
#define MAX_CLIENTS 20000
#define MAXEVENTS 128
#define BUFFER_SIZE 4096
#define HEADER "HTTP/1.1 200 OK\r\nContent-type: text/javascript\r\nServer: Filement\r\n\r\n"
#define HEADER_LEN 68
#define HEADER_BUSY "HTTP/1.1 200 OK\r\nContent-type: text/javascript\r\nServer: Filement\r\n\r\nbusykey();"
#define HEADER_LEN_BUSY 78
#define ERROR_LOOP 5
static int findend(char buffer[], int size);

struct ev_buffer {
char *buf;
size_t len;
size_t offset;
};

struct ev_conn {
int sock;
struct ev_buffer *buffer;
};

struct fd {
int sock;
char is_admin;
struct ev_buffer *buffer;
int cur_ptr;
};

struct ev_conn *ev_conn_ptr=NULL;
int cur_ptr=0;

void ev_buffer_free(struct ev_buffer *tmp);

struct ev_buffer *ev_buffer_alloc(ssize_t len)
{
	struct ev_buffer *tmp=NULL;

	tmp=(struct ev_buffer *)malloc(sizeof(struct ev_buffer));
	fprintf(stderr,"%d\n",tmp);
	if(len)
	{
		tmp->len=len;
		tmp->offset=0;
		tmp->buf=(char *)malloc(sizeof(char)*len);
	}
	else tmp->buf=NULL;
	
	return tmp;
}

struct fd *fd_alloc(int sock)
{
	struct fd *tmp=NULL;
	
	tmp=(struct fd *)malloc(sizeof(struct fd));
	tmp->sock=sock;
	tmp->cur_ptr=-1;
	tmp->is_admin=0;
	tmp->buffer=NULL;
	
	return tmp;
}

void fd_close(struct fd *tmp)
{
struct ev_conn *tmpptr=NULL;
	if(tmp->sock)close(tmp->sock);
	tmp->sock=0;
	if(tmp->cur_ptr!=-1)
	{
	tmpptr=ev_conn_ptr+tmp->cur_ptr;
	if(tmpptr->buffer!=NULL)ev_buffer_free(tmpptr->buffer);
	tmpptr->buffer=NULL;
	//nikov
	if(tmpptr->sock)close(tmpptr->sock);
	tmpptr->sock=0;
	}
}

void ev_buffer_free(struct ev_buffer *tmp)
{
	if(tmp!=NULL)
	{
	if(tmp->buf!=NULL)free(tmp->buf);
	free(tmp);
	}
}

static int
make_socket_non_blocking (int sfd)
{
  int flags, s;

  flags = fcntl (sfd, F_GETFL, 0);
  if (flags == -1)
    {
      perror ("fcntl");
      abort();
    }

  flags |= O_NONBLOCK;
  s = fcntl (sfd, F_SETFL, flags);
  if (s == -1)
    {
      perror ("fcntl");
      abort();
    }

  return 0;
}

static int
create_and_bind (char *port)
{
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int s, sfd;

  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_UNSPEC;     /* Return IPv4 and IPv6 choices */
  hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */
  hints.ai_flags = AI_PASSIVE;     /* All interfaces */

  s = getaddrinfo (NULL, port, &hints, &result);
  if (s != 0)
    {
      fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (s));
      abort();
    }

  for (rp = result; rp != NULL; rp = rp->ai_next)
    {
      sfd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if (sfd == -1)
        continue;
		
	int optval = 1;
		setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

      s = bind (sfd, rp->ai_addr, rp->ai_addrlen);
      if (s == 0)
        {
          /* We managed to bind successfully! */
          break;
        }

      close (sfd);
    }

  if (rp == NULL)
    {
      fprintf (stderr, "Could not bind\n");
      abort();
    }

  freeaddrinfo (result);

  return sfd;
}

int
main (int argc, char *argv[])
{
  int cl_sfd,adm_sfd, s,u;
  int efd;
  char small_buf[10];
  struct epoll_event event;
   struct epoll_event event2;
  struct epoll_event *events;
  struct ev_conn *tmpptr=NULL;
  struct rlimit limit;
  long maxfd = MAX_FD;
  //allocate and check memory
  
  
  
      limit.rlim_cur = maxfd;
	  limit.rlim_max = maxfd;
      if ( setrlimit( RLIMIT_NOFILE, &limit ) == -1 ) {
	perror( "unable to set new soft limit" );
	return 1;
      }
    
  /* obtain hard/soft limit */
  if ( getrlimit( RLIMIT_NOFILE, &limit ) == -1 ) {
    perror( "unable to obtain limits" );
    return 1;
  } else {
    printf( "FD limit = { hard : %d, soft : %d }\n",
	    limit.rlim_max, limit.rlim_cur );
  }
  
  ev_conn_ptr=(struct ev_conn *) malloc(sizeof(struct ev_conn)*MAX_CLIENTS);
  if (ev_conn_ptr == NULL) {
		fprintf(stderr,"malloc can't allocate memory !!!");
		return 0;
	}
  //

 //bind on the client port
	fprintf(stderr,"Binding on the client port...\n");
  cl_sfd = create_and_bind (CLIENT_PORT);
  if (cl_sfd == -1)
    abort();

  s = make_socket_non_blocking (cl_sfd);
  if (s == -1)
    abort();

  s = listen (cl_sfd, SOMAXCONN);
  if (s == -1)
    {
      perror ("listen");
      abort();
    }

  efd = epoll_create1 (0);
  if (efd == -1)
    {
      perror ("epoll_create");
      abort();
    }
fprintf(stderr,"Client sfd %d\n",cl_sfd);
  event.data.ptr =  fd_alloc(cl_sfd);;
//  event.data.u64 = 0;
//  event.data.u32 = 0;
  event.events = EPOLLIN | EPOLLET;
  s = epoll_ctl (efd, EPOLL_CTL_ADD, cl_sfd, &event);
  if (s == -1)
    {
      perror ("epoll_ctl");
      abort();
    }
	
 //bind on the admin port
	fprintf(stderr,"Binding on the admin port...\n");
  adm_sfd = create_and_bind (ADMIN_PORT);
  if (adm_sfd == -1)
    abort();

  s = make_socket_non_blocking (adm_sfd);
  if (s == -1)
    abort();

  s = listen (adm_sfd, SOMAXCONN);
  if (s == -1)
    {
      perror ("listen");
      abort();
    }

fprintf(stderr,"Admin sfd %d\n",adm_sfd);
  event2.data.ptr = fd_alloc(adm_sfd);
//  event2.data.u64 = 0;
//  event2.data.u32 = 0;
  event2.events = EPOLLIN | EPOLLET;
  s = epoll_ctl (efd, EPOLL_CTL_ADD, adm_sfd, &event2);
  if (s == -1)
    {
      perror ("epoll_ctl");
      abort();
    }

  /* Buffer where events are returned */
  events = calloc (MAXEVENTS, sizeof event);

  /* The event loop */
  while (1)
    {
      int n, i;

      n = epoll_wait (efd, events, MAXEVENTS, -1);
	  
      for (i = 0; i < n; i++)
	{
	struct fd *tmpfd=events[i].data.ptr;
		fprintf(stderr,"wait stopped with %d events fd %d\n",n,tmpfd->sock);
		//continue;
	  if ((events[i].events & EPOLLERR) ||
              (events[i].events & EPOLLHUP) ||
              (!(events[i].events & EPOLLIN)))
	    {
              /* An error has occured on this fd, or the socket is not
                 ready for reading (why were we notified then?) */
	      fprintf (stderr, "epoll error closing the socket or not error maybe\n");
			
	      fd_close(tmpfd);
	      continue;
	    }
	
	  else if (adm_sfd == tmpfd->sock)
	    {
			fprintf(stderr,"admin connection\n");
              /* We have a notification on the listening socket, which
                 means one or more incoming connections. */
              while (1)
                {
			      struct fd *allocfd=NULL;
                  struct sockaddr in_addr;
                  socklen_t in_len;
                  int infd;
                  char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

                  in_len = sizeof in_addr;
                  infd = accept (adm_sfd, &in_addr, &in_len);
                  if (infd == -1)
                    {
                      if ((errno == EAGAIN) ||
                          (errno == EWOULDBLOCK))
                        {
                          /* We have processed all incoming
                             connections. */
                          break;
                        }
                      else
                        {
                          perror ("accept");
                          break;
                        }
                    }
					
				//TODO da comentiram dolniq zapis, poneje e izlishen ama sega za debug 6te go ostavq
                  s = getnameinfo (&in_addr, in_len,
                                   hbuf, sizeof hbuf,
                                   sbuf, sizeof sbuf,
                                   NI_NUMERICHOST | NI_NUMERICSERV);
                  if (s == 0)
                    {
                      printf("Accepted Admin connection on descriptor %d "
                             "(host=%s, port=%s)\n", infd, hbuf, sbuf);
                    }

                  /* Make the incoming socket non-blocking and add it to the
                     list of fds to monitor. */
                  s = make_socket_non_blocking (infd);
                  if (s == -1)
                    abort();
					allocfd=fd_alloc(infd);
					allocfd->is_admin=1;
                  event.data.ptr = allocfd;
				  //event.data.u32 = 1;
                  event.events = EPOLLIN | EPOLLET;
                  s = epoll_ctl (efd, EPOLL_CTL_ADD, infd, &event);
                  if (s == -1)
                    {
                      perror ("epoll_ctl");
                      abort();
                    }
                }
              continue;
        }
		else if (cl_sfd == tmpfd->sock)
	    {
			fprintf(stderr,"client connection\n");
              /* We have a notification on the listening socket, which
                 means one or more incoming connections. */
              while (1)
                {
                  struct sockaddr in_addr;
                  socklen_t in_len;
                  int infd;
                  char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

                  in_len = sizeof in_addr;
                  infd = accept (cl_sfd, &in_addr, &in_len);
                  if (infd == -1)
                    {
                      if ((errno == EAGAIN) ||
                          (errno == EWOULDBLOCK))
                        {
                          /* We have processed all incoming
                             connections. */
                          break;
                        }
                      else
                        {
                          perror ("accept");
                          break;
                        }
                    }
					//TODO da comentiram dolniq zapis, poneje e izlishen ama sega za debug 6te go ostavq
                  s = getnameinfo (&in_addr, in_len,
                                   hbuf, sizeof hbuf,
                                   sbuf, sizeof sbuf,
                                   NI_NUMERICHOST | NI_NUMERICSERV);
                  if (s == 0)
                    {
                      printf("Accepted Client connection on descriptor %d "
                             "(host=%s, port=%s)\n", infd, hbuf, sbuf);
                    }

                  /* Make the incoming socket non-blocking and add it to the
                     list of fds to monitor. */
                  s = make_socket_non_blocking (infd);
                  if (s == -1)
                    abort();

                  event.data.ptr = fd_alloc(infd);
                  event.events = EPOLLIN | EPOLLET;
                  s = epoll_ctl (efd, EPOLL_CTL_ADD, infd, &event);
                  if (s == -1)
                    {
                      perror ("epoll_ctl");
                      abort();
                    }
                }
              continue;
        }
        else
            {
              /* We have data on the fd waiting to be read. Read and
                 display it. We must read whatever data is available
                 completely, as we are running in edge-triggered mode
                 and won't get a notification again for the same
                 data. */
              int done = 0;
			fprintf(stderr,"check\n");
				if(tmpfd->is_admin)//admin socket
				{
				  ssize_t count=0;
				  int local_ptr=-1;
				  int buf_i=0;
				  if(tmpfd->buffer==NULL)
				  {
				  tmpfd->buffer=ev_buffer_alloc(BUFFER_SIZE);
				  tmpfd->buffer->len=0;
				  }
				  fprintf(stderr,"buffer ne e null\n");
				   char *buf=tmpfd->buffer->buf;
                  
				 while (1)
                {
					
					if(tmpfd->buffer->len>=BUFFER_SIZE)
						{
						fprintf(stderr,"max buffer size reached\n");
							done=1;
							break;
						}
                  count = read (tmpfd->sock, buf+tmpfd->buffer->len, (BUFFER_SIZE-tmpfd->buffer->len));
				  fprintf(stderr,"4ete ot admin\n");
				  write(0,buf+tmpfd->buffer->len,count);
                  if (count == -1)
                    {
                      /* If errno == EAGAIN, that means we have read all
                         data. So go back to the main loop. */
                      if (errno != EAGAIN)
                        {
                          perror ("read");
                          done = 1;
                        }
                      break;
                    }
                  else if (count == 0)
                    {
                      /* End of file. The remote has closed the
                         connection. */
                      done = 1;
                      break;
                    }
					tmpfd->buffer->len+=count;
				fprintf(stderr,"tmpfd->buffer->len e %d\n",tmpfd->buffer->len);
					
					

                  /* Write the buffer to standard output */
				 
				 if(tmpfd->cur_ptr<0)
				 {
				  if(buf[0]=='\n' || buf[0]=='\r') // new key
				  {
					u=0;
					while(u<ERROR_LOOP) //TODO to fix this da po4ne da 4isti socketite kogato sa na 80% pulni
					{
					fprintf(stderr,"vleze v cikula i vurti u\n");
						cur_ptr++;
						if(cur_ptr==MAX_CLIENTS)
						{
						cur_ptr=1;
						u++;
						}
						tmpptr=ev_conn_ptr+cur_ptr;
						if(!tmpptr->sock && tmpptr->buffer==NULL)
						{
						fprintf(stderr,"cur_ptr e %d\n",cur_ptr);
						sprintf(small_buf, "%d", cur_ptr); 
						//key generation
						fprintf(stderr,"small_buf e %s\n",small_buf);
						write(tmpfd->sock,small_buf,strlen(small_buf));
						fprintf(stderr,"brum2\n");
						//tmpfd->cur_ptr=cur_ptr;
						//adding the socket to the memory
						//tmpptr->sock=tmpfd->sock;
						
						break;
						}
						
					}
					if(u==ERROR_LOOP)
						{
						fprintf(stderr,"no free fds\n");
						write(tmpfd->sock,"ERROR",5);
						//TODO to send reconnect signals to the clients and to free the all fds
						abort();
						}
				  
						fprintf(stderr,"key %d\n",cur_ptr);
						done=1;
						break;
				  
				  }
				  else
				  {
				  fprintf(stderr,"chete admina kum koi client 6te se vurje\n");
				 
				 // write (0, buf, count);
				  
				  for(buf_i=0;buf_i<9 && *(buf+buf_i)!='\n' && *(buf+buf_i)!='\r';buf_i++)small_buf[buf_i]=*(buf+buf_i);
				  small_buf[buf_i]='\0';
				  local_ptr=strtol(small_buf, NULL, 10);
				  fprintf(stderr,"local_ptr se okaza %d\n",local_ptr);
				  tmpfd->buffer->offset=(buf_i+1);
					if(tmpfd->buffer->offset>tmpfd->buffer->len)
						{
							fprintf(stderr,"ERROR , the offset is bigger than the len.This should not happen\n");
							return -1;
						}
						
				 
				  if(!local_ptr || local_ptr>MAX_CLIENTS)
					{
					fprintf(stderr,"ERROR wrong number\n");
					write(tmpfd->sock,"ERROR",5);
					close(tmpfd->sock);
					tmpfd->sock=0;
					break;
					//error
					}
					tmpfd->cur_ptr=local_ptr;
					fprintf(stderr,"DEBUG count %d\n",count);
					fprintf(stderr,"DEBUG buf_i %d\n",buf_i);
				  }
				 }
				  
				  
  
				}
				
				if (done)
                {
				
				if((tmpfd->cur_ptr)>=0)
				{
					tmpptr=ev_conn_ptr+tmpfd->cur_ptr;
					//buf[count]='\0';//TODO tova da go vidq dali nqma da otreje posledniq symbol
				  if(tmpptr->sock)
				  {
				  fprintf(stderr,"ima clientski socket za %d i pi6e v nego\n",tmpfd->cur_ptr);
				  s = write (tmpptr->sock, tmpfd->buffer->buf+tmpfd->buffer->offset, tmpfd->buffer->len-tmpfd->buffer->offset);
				  s = write (0, tmpfd->buffer->buf+tmpfd->buffer->offset, tmpfd->buffer->len-tmpfd->buffer->offset);
                  if (s == -1)
                    {
                      perror ("write");
					  write(tmpfd->sock,"ERROR",5);
					  close(tmpfd->sock);
					  tmpfd->sock=0;
					  //nikov
					  if(tmpptr->sock){close(tmpptr->sock);tmpptr->sock=0;}
					  ev_buffer_free(tmpfd->buffer);
					  tmpfd->buffer=NULL;
					  break;
                    }
					
					//closing the client socket
					
					if(tmpptr->sock)close(tmpptr->sock);
					tmpptr->sock=0;
					ev_buffer_free(tmpfd->buffer);
					tmpfd->buffer=NULL;
					//if(tmpptr->buffer!=NULL)ev_buffer_free(tmpptr->buffer);
					
				   
				   }
				   else 
				   {
				   fprintf(stderr,"zapisva v buffer za %d golqm %d,\n",tmpfd->cur_ptr,tmpfd->buffer->len);
				   tmpptr->buffer=tmpfd->buffer;
				   
				   }
				   
				}
				 
                  printf ("Closed connection on descriptor %d\n",
                          tmpfd->sock);

                  /* Closing the descriptor will make epoll remove it
                     from the set of descriptors which are monitored. */
					 tmpfd->buffer=NULL;
                  close (tmpfd->sock);
                }
				
				}
				else // client socket
				{
				char buf[BUFFER_SIZE];
				  long int local_ptr=-1;
				  int buf_i=0;
				  int tmp=0;
				  int i=0;
				  int error=0;
				  ssize_t count;
					while (1)
					{
                  ssize_t count;
                  

                  count = read (tmpfd->sock, buf,BUFFER_SIZE);
				  fprintf(stderr,"client count %d\n",count);
                  if (count == -1)
                    {
                      /* If errno == EAGAIN, that means we have read all
                         data. So go back to the main loop. */
                      if (errno != EAGAIN)
                        {
                          perror ("read");
                          done = 1;
                        }
                      break;
                    }
                  else if (count == 0)
                    {
                      /* End of file. The remote has closed the
                         connection. */
                      done = 1;
                      break;
                    }
					
					if (strncmp(buf,"GET ",4))
							{
							break; 
							}
							
					for(i=0;i<count;i++)
					{
						fprintf(stderr,"%c %d\n",buf[i],i);
						if(buf[i]=='\r' || buf[i]=='\n')
						{
						break;
						}
					}
					if(i==count)
						{
							fprintf(stderr,"strange error in http protocol\n");
							fd_close(tmpfd);
							break;
						}
					fprintf(stderr,"i e %d\n",i);
					count=i;
					 
					if(count <5)
							{
							fprintf(stderr,"ERROR count out of boundaries\n");
							error=1;
							break;
							}
						
						
						
						fprintf(stderr,"buf+4 e %c\n",*(buf+4));
						buf_i=findend(buf+4,count);
						fprintf(stderr,"bif_i e %d\n",buf_i);
						buf[buf_i+4]='\0';
						tmp=buf_i;
						
						for(;buf[buf_i+4]!='/' && buf_i>0;buf_i--);
						if((tmp-(buf_i+1))>9)
							{
							fprintf(stderr,"ERROR count out of boundaries 2\n");
							
							error=1;
							break;
							}
						tmp=0;
						
						local_ptr = strtol(buf+4+buf_i+1, NULL, 10);
						fprintf(stderr,"local_ptr e %lld\n",local_ptr);
						if(local_ptr==0)
							{
							fprintf(stderr,"ERROR local_ptr is 0 for some reason\n");
							
							error=1;
							break;
								
							}
						if(local_ptr>MAX_CLIENTS)
						{
							fprintf(stderr,"ERROR local_ptr %ld",local_ptr);
							
							error=1;
							break;	
						}
						
						tmpptr=ev_conn_ptr+local_ptr;
						if(tmpptr->sock)
						{
							fprintf(stderr,"ERROR tmpptr->sock %d",tmpptr->sock);
							
							error=1;
							break;	
						}
						tmpptr->sock=tmpfd->sock;
						tmpfd->cur_ptr=local_ptr;
						done=1;
					}
					
					if(error)
					{
					s = write (tmpfd->sock, HEADER_BUSY, HEADER_LEN_BUSY);
					
					fd_close(tmpfd);tmpfd->sock=0;
					}
					else if (done && tmpfd->cur_ptr!=-1)
					{
					tmpptr=ev_conn_ptr+tmpfd->cur_ptr;
					s = write (tmpptr->sock, HEADER, HEADER_LEN);
					
						if(tmpptr->buffer!=NULL)
						{
						fprintf(stderr,"buffer ne e NULL len e %d\n",tmpptr->buffer->len);
						fprintf(stderr,"offset\n");
						fprintf(stderr,"buffer ne e NULL offset e %d\n",tmpptr->buffer->offset);
						//for(i=0;i<tmpptr->buffer->len;i++)fprintf(stderr,"%c %d\n",tmpptr->buffer->buf);
						s = write (tmpptr->sock, tmpptr->buffer->buf+tmpptr->buffer->offset, tmpptr->buffer->len-tmpptr->buffer->offset);
						write(0,tmpptr->buffer->buf+tmpptr->buffer->offset,tmpptr->buffer->len-tmpptr->buffer->offset);
						fprintf(stderr,"close\n");
						fd_close(tmpfd);
						tmpptr->sock=0;
						fprintf(stderr,"sock 0\n");
						ev_buffer_free(tmpptr->buffer);
						fprintf(stderr,"free\n");
						tmpptr->buffer=NULL;
						
						}
				
				
					}
					else if(done)
					{
					fprintf(stderr,"nqma cur_ptr i e done taka 4e zatvarq conneciqta\n");
					fd_close(tmpfd);tmpfd->sock=0;
					}
				
				
				}

              
            }
        }
    }

  free (events);

  close (adm_sfd);
  close (cl_sfd);


  return EXIT_SUCCESS;
}

static int findend(char buffer[], int size)
{
	int i;
	for(i = 0; i < size; ++i)
		if (buffer[i] == (char)' ')
			return i;
	return -1;
}
