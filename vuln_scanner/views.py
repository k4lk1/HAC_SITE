
from urllib.parse import urlparse
from django.shortcuts import render, redirect
from django.template import loader
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.template.loader import get_template
from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView, View
from newsapi import NewsApiClient
from .utils import render_to_pdf
from .models import site,reviews
import re
from .status import  read_sqli,read_lfi,read_xss, read_idor
import subprocess,os
from .read_status import read_status_lfi,read_status_idor,read_status_xss,read_status_sqli
from plumbum.cmd import cut,echo
from background_task import background
from celery.decorators import task
from .task import scan
# shows the dashboard 
"""@login_required(login_url="/login")            subprocess.call(['bash','script.sh', url ])

def index(request):
    context = {
        "urls" : site.objects.all(),
        "news" : getNews(),

        "review": reviews.objects.all(),
    }
    def form_valid(self, form):
        form.instance.author = self.request.user   
        return super().form_valid(form)
    
    queryset= site.objects.all()
    def get_queryset(self):
        return self.queryset.filter(author=self.request.user) 
    
   

    template = loader.get_template('vuln_scanner/dashboard.html')
    return HttpResponse(template.render(context, request))"""

# function for getting the latest Cyber Security news 
def getNews():
    # Init
    newsapi = NewsApiClient(api_key='9bf1a3489aba49b8aa69a35b5105e4cc')

    # /v2/top-headlines
    top_headlines = newsapi.get_everything(domains='threatpost.com',page_size=10)
    
    # getting all articles in a string article 
    article = top_headlines["articles"] 
  
    # empty list which will  
    # contain all trending news 
    results = [] 

    for ar in article: 
        results.append([ar["title"],ar["author"],ar["url"]]) 

    return results
"""
@login_required(login_url="/login")
def SiteReview(request):
    context = {
        "review": reviews.objects.all(),
    }
    template = loader.get_template('vuln_scanner/reviews.html')
    return HttpResponse(template.render(context, request))"""

class SiteReview(LoginRequiredMixin,CreateView):
    login_url='/login/'
    model=reviews
    fields={'email_id','feedback'}
    template_name='vuln_scanner/reviews.html'
    success_url='/dashboard/'
    context_object_name='review'



       


# view for getting input URL for scanning
class SiteInput(LoginRequiredMixin,CreateView):
    login_url = '/login/'
    model=site
    fields={'site_url'}
    template_name='vuln_scanner/index.html'
    success_url='dashboard/'
    
    
    def form_valid(self, form):
        if form.is_valid():
            url=form.cleaned_data['site_url']
            scan.delay(url)
            form.instance.author = self.request.user   
            return super().form_valid(form)
        
        

  
# view for displaying list of scanned urls
class SiteListView(LoginRequiredMixin,ListView):
    login_url = '/login/'
    model=site
    template_name='vuln_scanner/dashboard.html'

    
    def get_context_data(self, **kwargs):
        context=super().get_context_data(**kwargs)
        context['urls']=site.objects.all().filter(author=self.request.user)
        context['news']=getNews()
        return context
    ordering=['date_posted']
   
    
    
        
class SiteDetailView(LoginRequiredMixin,DetailView):
    login_url = '/login/'
    model=site
    template_name='vuln_scanner/details.html'
    def get_context_data(self,*args,**kwargs):
        context=super().get_context_data(**kwargs)
        context['urls']=site.objects.all()
        context['site']=site.objects.all().filter(id=self.kwargs['pk']).last().site_url
        url=context['site']
        url=url.split("/")
        url=url[2]
        context['sqli_status']=read_sqli(self.request,url)
        context['idor_status']=read_idor(self.request,url)
        context['xss_status']=read_xss(self.request,url)
        context['lfi_status']=read_lfi(self.request,url)
        return context
    

   

class SiteDeleteView(LoginRequiredMixin, UserPassesTestMixin, DeleteView):
    login_url = '/login/'
    model=site
    template_name='vuln_scanner/details_confirm_delete.html'
    url=site.objects.filter(id=1)
    success_url='/dashboard/'
    def test_func(self):
        site=self.get_object()
        if self.request.user == site.author:
            return True
        elif self.request.user.is_superuser:
            return True
        return False
    
    

class GeneratePDF(LoginRequiredMixin,View):
    model=site
    

    def get(self, request, *args, **kwargs):
        template = get_template('pdf/invoice.html')
        url=site.objects.all().filter(id=self.kwargs['pk']).last().site_url
        url=url.split("/")
        url=url[2]
        #url=site.objects.all().filter(id=self.kwargs['pk']).last().site_url
        #print(url)
        context = {
            "client": site.objects.all().filter(id=self.kwargs['pk']).first().author,
            "urls" : site.objects.all().filter(id=self.kwargs['pk']).last().site_url,
            
            "sqli_status":read_sqli(self.request,url),
            "lfi_status":read_lfi(self.request,url),
            "idor_status":read_idor(self.request,url),
            "xss_status":read_idor(self.request,url),
            "date":site.objects.all().filter(id=self.kwargs['pk']).last().date_posted,
        }
        html = template.render(context)
        pdf = render_to_pdf('pdf/invoice.html', context)
        if pdf:
            response = HttpResponse(pdf, content_type='application/pdf')
            filename = "report.pdf" 
            content = "inline; filename='%s'" %(filename)
            download = request.GET.get("download")
            if download:
                content = "attachment; filename='%s'" %(filename)
            response['Content-Disposition'] = content
            return response
        return HttpResponse("Not found")

class ReadStatusLFI(DetailView):
    login_url = '/login/'
    model=site
    template_name='logs/lfi.html'
    def get_context_data(self,*args,**kwargs):
        context=super().get_context_data(**kwargs)
        context['site']=site.objects.all().filter(id=self.kwargs['pk']).last().site_url
        url=context['site']
        url=url.split("/")
        url=url[2]
        context['lfi_status']=read_status_lfi(self.request,url)
        return context

class ReadStatusIDOR(DetailView):
    login_url = '/login/'
    model=site
    template_name='logs/idor.html'
    def get_context_data(self,*args,**kwargs):
        context=super().get_context_data(**kwargs)
        context['site']=site.objects.all().filter(id=self.kwargs['pk']).last().site_url
        url=context['site']
        url=url.split("/")
        url=url[2]
        context['idor_status']=read_status_idor(self.request,url)
        return context

class ReadStatusSQLI(DetailView):
    login_url = '/login/'
    model=site
    template_name='logs/sqli.html'
    def get_context_data(self,*args,**kwargs):
        context=super().get_context_data(**kwargs)
        context['site']=site.objects.all().filter(id=self.kwargs['pk']).last().site_url
        url=context['site']
        url=url.split("/")
        url=url[2]
        context['sqli_status']=read_status_sqli(self.request,url)
        return context

class ReadStatusXSS(DetailView):
    login_url = '/login/'
    model=site
    template_name='logs/xss.html'
    def get_context_data(self,*args,**kwargs):
        context=super().get_context_data(**kwargs)
        context['site']=site.objects.all().filter(id=self.kwargs['pk']).last().site_url
        url=context['site']
        url=url.split("/")
        url=url[2]
        context['xss_status']=read_status_xss(self.request,url)
        return context


