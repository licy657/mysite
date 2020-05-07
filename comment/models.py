import threading
from django.db import models
from django.conf import settings
from django.core.mail import send_mail
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import User
from django.template.loader import render_to_string


class SendMail(threading.Thread):
    def __init__(self, subjects, text, email, fail_silently=False):
        self.subjects = subjects
        self.text = text
        self.email = email
        self. fail_silently = fail_silently
        threading.Thread.__init__(self)
    def run(self):
        send_mail(
            self.subjects,
            '',
            settings.EMAIL_HOST_USER,
            [self.email],
            fail_silently=self.fail_silently,
            html_message=self.text
        )

class Comment(models.Model):
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    content_object = GenericForeignKey('content_type', 'object_id')

    text = models.TextField()
    commtent_time = models.DateField(auto_now_add=True)
    user = models.ForeignKey(User, related_name="comments", on_delete=models.CASCADE)

    root = models.ForeignKey('self', related_name='root_comment', null=True, on_delete=models.CASCADE)
    parent = models.ForeignKey('self', related_name='parent_comment', null=True, on_delete=models.CASCADE)
    reply_to = models.ForeignKey(User, related_name="replies", null=True,  on_delete=models.CASCADE)

    def send_mail(self):
        if self.parent is None:
            # 评论我的博客
            # 发送邮件
            subjects = '有人评论你的博客'
            email = self.content_object.get_email()
        else:
            # 回复评论
            subjects = '有人回复你的评论'
            email = self.reply_to.email
        if email != '':
            # text = '%s\n<a href="%s">%s</a>' % (self.text, self.content_object.get_url(), '点击查看')
            # text = self.text + '\n' + self.content_object.get_url()
            context = {}
            context['comment_text'] = self.text
            context['url'] = self.content_object.get_url()
            text = render_to_string('comment/send_mail.html', context)
            send_mail = SendMail(subjects, text, email)
            send_mail.start()


    def __str__(self):
        return self.text

    class Meta:
        ordering = ['commtent_time']
