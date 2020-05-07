from django.shortcuts import render, redirect, reverse
from django.http import JsonResponse
from django.core.mail import send_mail

from .models import Comment
from .forms import CommentForm


# 提交评论
def update_comment(request):

    comment_form = CommentForm(request.POST, user=request.user)
    data = {}

    if comment_form.is_valid():
        # 检查通过，保存数据
        comment = Comment()
        comment.user = comment_form.cleaned_data['user']
        comment.text = comment_form.cleaned_data['text']
        comment.content_object = comment_form.cleaned_data['content_object']

        parent = comment_form.cleaned_data['parent']
        if not parent is None:
            comment.root = parent.root if parent.root else parent
            comment.parent = parent
            comment.reply_to = parent.user
        comment.save()

        # 发送邮件
        comment.send_mail()

        # 返回数据
        data['status'] = 'success'
        data['username'] = comment.user.get_nickname_or_username()
        data['comment_time'] = comment.commtent_time.strftime('%Y-%m-%d %H:%M:%S')
        data['text'] = comment.text
        if parent is not None:
            data['rely_to'] = comment.reply_to.get_nickname_or_username()
        else:
            data['reply_to'] = ''
        data['pk'] = comment.pk
        data['root_pk']  = comment.root.pk if comment.root else ''
    else:
        data['status'] = 'error'
        data['message'] = list(comment_form.errors.values())[0][0]
    return JsonResponse(data)